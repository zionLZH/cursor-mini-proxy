# cursor-gateway

把 **Cursor Agent 私有协议**封装为 **OpenAI 兼容 HTTP 服务器**的单文件 Go 程序。

- 单文件实现（`main.go`，约 1300 行），**零第三方依赖**（仅 Go 标准库）
- 对外：OpenAI 兼容的 `/v1/models` + `/v1/chat/completions`（支持 SSE 流式），任何 OpenAI SDK / 客户端可直接对接
- 对内：直连 Cursor 后端（`api2.cursor.sh`），复刻 `cursor-agent` 的 connect+proto / HTTP/2 全双工聊天协议
- 内置：PKCE 浏览器登录、凭据缓存（按 authId 做 key）、token 过期自动刷新（single-flight 合并并发）
- 透传代理：请求头 `X-Proxy` 指定 http / https / socks5 代理，到 Cursor 上游的全部流量经代理转发（零依赖自实现 SOCKS5）

---

## 一、怎么编译

### 环境要求

- Go ≥ 1.22（代码使用了 Go 1.22 的 `ServeMux` 方法路由）
- 无需网络下载任何依赖，离线可编译

> 注：`go.mod` 中声明的是 `go 1.26.4`。如本机 Go 版本较低，把 `go.mod` 里该行改成本机版本（如 `go 1.22`）即可编译。

### 编译

```bash
cd cursor-gateway
go build -o cursor-gateway .        # 生成可执行文件
```

跨平台编译（可选）：

```bash
GOOS=linux   GOARCH=amd64 go build -o cursor-gateway-linux .
GOOS=windows GOARCH=amd64 go build -o cursor-gateway.exe .
GOOS=darwin  GOARCH=arm64 go build -o cursor-gateway-mac .
```

> `go.sum` 为空文件属正常现象（零依赖，无任何模块校验和）。

也可直接从 [Releases](https://github.com/zionLZH/cursor-mini-proxy/releases) 下载预编译产物：CI 在推送 `v*` 标签时自动交叉编译 6 个平台（linux / darwin / windows × amd64 / arm64），命名为 `cursor-gateway-<os>-<arch>`（Windows 为 `.exe`），并附带 `SHA256SUMS` 校验文件。

## 二、怎么运行

```bash
./cursor-gateway                          # 默认监听 127.0.0.1:8787
./cursor-gateway -port 9000               # 指定端口
./cursor-gateway -data creds.json         # 指定凭据缓存文件（默认 gateway-credentials.json）
./cursor-gateway -data ""                 # 禁用磁盘持久化（仅内存缓存）

# 可选：配置全局刷新凭据（任何 authId 缺失刷新凭据时兜底使用）
CURSOR_API_KEY=key_xxx ./cursor-gateway

# 调试：打印上下行原始帧（hex），排查协议问题用
GATEWAY_DEBUG=1 ./cursor-gateway
```

### 启动参数与环境变量

| 参数 / 环境变量 | 默认值 | 说明 |
|---|---|---|
| `-port` / `GATEWAY_PORT` | `8787` | 监听端口（仅绑定 127.0.0.1） |
| `-data` / `GATEWAY_DATA` | `gateway-credentials.json` | 凭据缓存文件路径；留空禁用持久化 |
| `GATEWAY_DEBUG` | 关 | 非空则打印上下行帧 hex（含对话内容，仅调试用） |
| `CURSOR_API_KEY` | 无 | 全局刷新凭据（token 过期且请求未带 API key 时兜底） |
| `CURSOR_API_BASE_URL` | `https://api2.cursor.sh` | 上游 API 地址 |
| `CURSOR_WEBSITE_URL` | `https://cursor.com` | 浏览器登录站点 |
| `CURSOR_CLIENT_VERSION` | `cli-2026.10.01-e373342` | 上行 `x-cursor-client-version` |

---

## 三、快速上手（三步）

```bash
# 1) 获取登录链接（浏览器打开 loginUrl 完成登录）
curl -X POST http://127.0.0.1:8787/v1/auth/login
# → {"loginUrl":"https://cursor.com/loginDeepControl?...","loginId":"<uuid>","expiresIn":600}

# 2) 轮询登录结果（202=未完成继续轮询；200=成功，返回 authId + token）
curl "http://127.0.0.1:8787/v1/auth/login/result?loginId=<uuid>"
# → {"authId":"google-oauth2|user_xxx","accessToken":"eyJ...","refreshToken":"eyJ...","expiresAt":1796966631}

# 3) 用拿到的凭据调用 OpenAI 兼容接口
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer <accessToken>" \
  -H "X-Cursor-Auth-Id: <authId>" \
  -H "Content-Type: application/json" \
  -d '{"model":"default","messages":[{"role":"user","content":"你好"}]}'
```

## 四、HTTP 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/auth/login` | 创建登录会话，返回浏览器授权链接 |
| GET | `/v1/auth/login/result` | 轮询登录结果（长轮询 ~10s），返回 authId + token |
| GET | `/v1/models` | 模型列表（OpenAI 格式） |
| POST | `/v1/chat/completions` | 聊天补全（OpenAI 兼容，支持 SSE 流式） |
| GET | `/v1/credentials` | 查看缓存中的凭据（脱敏，不含 token 明文） |
| GET | `/health` | 健康检查 |
| OPTIONS | `/` | CORS 预检 |

### 4.1 POST /v1/auth/login —— 发起授权登录

- 请求：无 body
- 响应 `200`：

```json
{
  "loginUrl": "https://cursor.com/loginDeepControl?challenge=...&uuid=...&mode=login&redirectTarget=cli",
  "loginId": "149652c5-7659-49be-b669-40929a2ead2e",
  "expiresIn": 600
}
```

把 `loginUrl` 交给用户在浏览器打开（点击登录即完成），`loginId` 用于第 2 步轮询。会话有效期 10 分钟。

### 4.2 GET /v1/auth/login/result?loginId=xxx —— 轮询登录结果

内部对上游做最多 ~10s 长轮询（每 1.5s 查询一次），调用方可直接循环调用。

| 状态码 | 响应 | 含义 |
|---|---|---|
| `200` | `{"authId":"google-oauth2|user_xxx","accessToken":"...","refreshToken":"...","expiresAt":1796966631}` | 登录成功 |
| `202` | `{"status":"pending","loginId":"..."}` | 用户尚未完成登录 |
| `403` | `{"error":{"message":"登录被拒绝..."}}` | 用户在页面拒绝 |
| `404` | loginId 不存在或已过期 | 重新调用 `/v1/auth/login` |

登录成功后，该 token 会**自动写入凭据缓存**（后续聊天可直接命中）。

### 4.3 GET /v1/models —— 模型列表

```bash
curl http://127.0.0.1:8787/v1/models \
  -H "Authorization: Bearer <accessToken>"
```

响应（OpenAI 格式，含 290+ 条目；displayModelId 与 aliases 均已展开）：

```json
{
  "object": "list",
  "data": [
    {"id": "default", "object": "model", "created": 1791781734, "owned_by": "cursor", "display_name": "Auto"},
    {"id": "composer-2.5", "object": "model", "created": 1791781734, "owned_by": "cursor", "display_name": "Composer 2.5"}
  ]
}
```

### 4.4 POST /v1/chat/completions —— 聊天（核心）

**请求体**（OpenAI 兼容）：

```json
{
  "model": "default",
  "messages": [
    {"role": "user", "content": "你好"}
  ],
  "stream": false
}
```

- `model`：缺省为 `default`；可选值见 `/v1/models`
- `messages[].content`：支持字符串，或 `[{"type":"text","text":"..."}]` 数组形式
- `stream`：`true` 返回 SSE 流

**非流式响应**（标准 `chat.completion`）：

```json
{
  "id": "chatcmpl-xxx",
  "object": "chat.completion",
  "model": "default",
  "choices": [{"index": 0, "message": {"role": "assistant", "content": "你好"}, "finish_reason": "stop"}],
  "usage": {"prompt_tokens": 6, "completion_tokens": 1, "total_tokens": 8}
}
```

> `usage` 为按字符数估算（len/4），非精确 tokenizer 计数。

**流式响应**（`stream: true`，`text/event-stream`）：

```
data: {"choices":[{"delta":{"role":"assistant","content":""},"finish_reason":null,"index":0}],...}
data: {"choices":[{"delta":{"content":"1、2、3、4、5。"},"finish_reason":null,"index":0}],...}
data: {"choices":[{"delta":{},"finish_reason":"stop","index":0}],...}
data: [DONE]
```

上游出错时，流中会输出一个 `data: {"error":{"message":"...","type":"upstream_error"}}` 事件后接 `[DONE]`。

**用 OpenAI SDK 直连**：

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8787/v1",
    api_key="<accessToken>",            # 会作为 Authorization: Bearer 发送
    default_headers={"X-Cursor-Auth-Id": "<authId>"},  # 可省略（自动从 token 的 sub 解析）
)
resp = client.chat.completions.create(
    model="default",
    messages=[{"role": "user", "content": "你好"}],
)
print(resp.choices[0].message.content)
```

### 4.5 GET /v1/credentials —— 查看凭据缓存（脱敏）

```json
{
  "credentials": [
    {
      "authId": "google-oauth2|user_xxx",
      "exp": 1796966631,
      "expiresAt": "2026-12-11T13:23:51+08:00",
      "hasKey": false,
      "updatedAt": "2026-10-12T13:23:51+08:00"
    }
  ]
}
```

## 五、认证方式（请求头三要素）

| 请求头 | 必选 | 说明 |
|---|---|---|
| `Authorization: Bearer <accessToken>` | 是 | 登录或刷新得到的 token |
| `X-Cursor-Auth-Id: <authId>` | 否 | 缓存 key；缺省时自动从 token 的 `sub` 字段解析 |
| `X-Cursor-Api-Key: <key_xxx>` | 否 | 刷新凭据；token 过期且缓存不可用时用于换新 token |
| `X-Proxy: <proxy-url>` | 否 | 上游代理，如 `http://127.0.0.1:7890`、`socks5://127.0.0.1:1080` |

可选头都不传时：未过期 token 直通；过期 token 且无缓存 → `401`，提示提供 API key 或重新登录。

### 透传代理（X-Proxy）

任意接口可带 `X-Proxy` 请求头，让 gateway 到 Cursor 上游的**全部出站流量**（聊天 / 模型列表 / token 刷新 / 登录轮询）经过指定代理：

```bash
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer <accessToken>" \
  -H "X-Proxy: http://127.0.0.1:7890" \
  -H "Content-Type: application/json" \
  -d '{"model":"auto","messages":[{"role":"user","content":"你好"}]}'
```

支持的写法：

| `X-Proxy` 值 | 协议 |
|---|---|
| `http://127.0.0.1:7890` | HTTP 代理（https 目标自动走 CONNECT 隧道） |
| `https://proxy.example.com:8443` | HTTPS 代理 |
| `socks5://127.0.0.1:1080` | SOCKS5 代理（NOAUTH；域名透传，等效 socks5h） |

- 不带该头 = 直连（默认行为）
- 地址非法 / 协议不支持 → `400`，提示明确原因
- 代理不可达时，错误信息会带 `proxyconnect` 字样便于排查

## 六、凭据缓存与刷新流程（核心机制）

**缓存 key = authId**（如 `google-oauth2|user_xxx`、`auth0|user_xxx`，即 token JWT 的 `sub`）。

```
请求到达
  │
  ├─ 传入 token 未过期（剩余 > 300s）──────────────→ 直通使用
  │
  └─ 传入 token 已过期/无法解析
       │
       ├─ 查缓存 [authId] 中有未过期 token ────────→ 用缓存 token
       │
       └─ 缓存无/已过期 → 找"刷新凭据"（优先级如下）
            │  ① 请求头 X-Cursor-Api-Key
            │  ② 缓存中该 authId 用过的 RefreshKey（用过一次即记住）
            │  ③ 环境变量 CURSOR_API_KEY
            │
            ├─ 找到 → 调 exchange_user_api_key 换新 token
            │         → 写缓存（同一 authId 并发请求合并为 1 次刷新，single-flight）
            │
            └─ 没找到 ──────────────────────────────→ 401「请提供 API key 或重新登录」
```

- 缓存持久化到 `gateway-credentials.json`（权限 0600），进程重启自动加载
- 刷新成功后会记住该 authId 使用的 API key（RefreshKey），后续该 authId 刷新无需再传
- 手动清缓存：停掉服务后删除 `gateway-credentials.json`（服务运行时仅删文件无效，内存会在下次写入时覆盖回文件）

### 关于 token 有效期的实测事实

| 凭据来源 | 有效期 | 能否自动刷新 |
|---|---|---|
| 浏览器登录（本网关 `/v1/auth/login`） | **60 天**（`type:"session"`） | 否——Cursor 无 OAuth 刷新端点；过期后重新登录，或改用 API key exchange |
| API key exchange（`X-Cursor-Api-Key`） | 1 小时（`type:"api_key_token"`） | 是——随时可再次 exchange，等效无限续期 |

> 登录响应中的 `refreshToken` 与 `accessToken` 是**同值副本**（Cursor 上游即如此返回），不能用于刷新，仅供业务侧登记 authId 使用。

## 七、协议说明（对内：网关 ↔ Cursor 后端）

### 7.1 Unary JSON 接口

- 端点发现：`POST {api}/aiserver.v1.ServerConfigService/GetServerConfig` → 取 `agentUrlConfig.agentUrl`（ghost）/ `agentnUrl`（普通）
- 模型列表：`POST {agent}/agent.v1.AgentService/GetUsableModels`
- 认证：`POST {api}/auth/exchange_user_api_key`（API key 换 token）、`GET {api}/auth/poll`（PKCE 登录轮询）
- 请求头：`connect-protocol-version: 1`、`content-type: application/json`、`x-cursor-client-version`、`x-cursor-client-type: cli` 等

### 7.2 聊天：HTTP/2 全双工 BiDi 流

- 端点：`POST {agent}/agent.v1.AgentService/Run`
- `Content-Type: application/connect+proto`，使用 Go 标准库 HTTP/2 全双工（`io.Pipe` 请求体 + 并发读响应）
- 帧格式：`[1B flag][4B 大端长度][protobuf payload]`
  - `flag & 0x01`：payload 为 gzip 压缩
  - `flag & 0x02`：trailer 帧（流结束，payload 为 JSON，含 error）
- **上行**（AgentClientMessage）：`#1 run_request` → 收到 `exec#10` 回 `request_context_result` + control → 收到 `exec#36` 回 `mcp_state_exec_result` + control → 每条 `kv_server_message` 立即 ack（首条序号 0 需回 `#3:{}`）→ 每 5s 发 `#7` 心跳
- **下行**（AgentServerMessage）：`exec_server_message`、`kv_server_message`、`interaction_update`（`#1` text_delta / `#4` thinking / `#14` turn_ended）、`conversation_checkpoint_update`（`#3`）、结束 trailer `{}`

## 八、实测验证结果

以下场景均已在真实账号上端到端验证通过：

| 场景 | 结果 |
|---|---|
| 非流式聊天 | 返回完整 OpenAI JSON |
| 流式 SSE 聊天 | role → content → `finish_reason:stop` → `[DONE]` |
| 模型列表 | 290+ 模型，OpenAI 格式 |
| 过期 token + 缓存命中 | 不触发刷新，直接成功 |
| 过期 token + API key 自动刷新 | `[refresh] 已刷新`，聊天成功 |
| 5 并发刷新合并（single-flight） | 只触发 1 次 exchange，全部 200 |
| 无凭据兜底 | 401 + 明确提示 |
| 浏览器登录闭环 | 返回 authId + 60 天 token，聊天验证成功 |

## 九、注意事项

1. **仅监听 127.0.0.1**（本机）；如需局域网访问，请自行修改 `main.go` 中的监听地址并注意加访问控制——该网关能读写你的 Cursor 凭据。
2. `gateway-credentials.json` 内含 API key 明文（权限已设 0600），**不要提交到 git 或分享**。
3. `GATEWAY_DEBUG=1` 的日志包含对话内容与帧数据，仅供排查问题，生产建议关闭。
4. 60 天 session token 过期后需重新走 `/v1/auth/login`（约 10 秒），或全程使用 API key exchange 路径。
5. 本网关依赖 Cursor 上游协议的现状（截至 `cli-2026.10.01-e373342`）；若上游协议变更，`Run` 流时序可能需要同步调整。
