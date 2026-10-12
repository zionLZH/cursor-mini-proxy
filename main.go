// cursor-gateway —— 将 Cursor Agent 私有协议封装为 OpenAI 兼容 HTTP 服务器
// ============================================================================
// 单文件实现，仅依赖 golang.org/x/net（HTTP/2 全双工流）。
//
// 功能：
//  1. 授权登录：POST /v1/auth/login 返回浏览器授权链接；轮询 /v1/auth/login/result
//     直至登录完成，返回 { authId("auth0"), accessToken, refreshToken }
//  2. OpenAI 兼容：GET /v1/models   POST /v1/chat/completions（支持 stream SSE）
//  3. 凭据缓存与刷新（核心）：
//     - 缓存 key = authId（auth0|user_xxx / google-oauth2|user_xxx，即 token 的 sub）
//     - 传入 token 未过期 → 直接直通
//     - 传入 token 已过期 → 查本地缓存：
//     · 有未过期缓存 → 用缓存
//     · 缓存也没有/已过期 → 用"刷新凭据"换新 token（API key exchange），写缓存
//     · 无刷新凭据 → 401，提示重新登录
//     - 刷新凭据优先级：请求头 X-Cursor-Api-Key > 缓存记录的 RefreshKey > 环境变量 CURSOR_API_KEY
//     - 同一 authId 并发刷新做 single-flight 合并
//  4. 透传代理：请求头 X-Proxy 传入代理（http / https / socks5），对 Cursor 上游的
//     全部出站流量（聊天 / 模型列表 / token 刷新 / 登录轮询）生效
//
// 调用协议（外部传入 auth0 和 token）：
//
//	GET /v1/models
//	  Authorization: Bearer <accessToken>
//	  X-Cursor-Auth-Id: <authId>                     （可选；缺省从 token 的 sub 解析）
//	  X-Cursor-Api-Key: <key_xxx>                    （可选；token 过期时用于刷新）
//	POST /v1/chat/completions
//	  { "model": "default", "messages": [{"role":"user","content":"你好"}], "stream": true }
//	  认证头同上。
//	可选：任何接口均可带 X-Proxy: http://127.0.0.1:7890（或 socks5://127.0.0.1:1080）经代理访问上游
//
// 用法：
//
//	go run ./cursor-gateway                        # 默认 127.0.0.1:8787
//	CURSOR_API_KEY=key_xxx go run ./cursor-gateway # 配置全局刷新凭据（可选）
//	环境变量：GATEWAY_PORT / GATEWAY_DATA / GATEWAY_DEBUG / CURSOR_API_KEY /
//	         CURSOR_API_BASE_URL / CURSOR_WEBSITE_URL / CURSOR_CLIENT_VERSION
//	启动参数：-port 8787  -data gateway-credentials.json
//	ghost 模式：请求 URL 加 ?ghost=true 开启
//
// 聊天协议要点（复刻自 cursor-agent 2026.10.01-e373342 抓包，缺一则回合挂起）：
//   - 上行：runRequest；exec#10(request_context_args) → 回 request_context_result + control；
//     exec#36(mcp_state) → 回 mcp_state_exec_result + control；每条 kv_server_message 立即 ack
//     （注意首条 kv 序号 0 被 proto3 省略，需回 kv_client_message{#3:{}}）；
//     每 5s 心跳 AgentClientMessage#7。
//   - 下行：interaction_update#1 text_delta / #4 thinking / #14 turn_ended；
//     checkpoint#3；结束时 trailer 帧 {}。
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================== 配置 ==============================

var (
	apiBase        = envOr("CURSOR_API_BASE_URL", "https://api2.cursor.sh")
	websiteBase    = envOr("CURSOR_WEBSITE_URL", "https://cursor.com")
	clientVersion  = envOr("CURSOR_CLIENT_VERSION", "cli-2026.10.01-e373342")
	defaultTimeout = 5 * time.Minute                  // 单次聊天总超时
	debugTx        = os.Getenv("GATEWAY_DEBUG") != "" // 打印上行帧 hex
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ============================== 小工具 ==============================

func mustUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randHex(n int) string {
	return hex.EncodeToString(randBytes(n))
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ============================== JWT（只读不校验签名） ==============================

func jwtClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

func jwtSub(token string) string {
	if c := jwtClaims(token); c != nil {
		if s, ok := c["sub"].(string); ok {
			return s
		}
	}
	return ""
}

func jwtExp(token string) int64 {
	if c := jwtClaims(token); c != nil {
		if v, ok := c["exp"].(float64); ok {
			return int64(v)
		}
	}
	return 0
}

// isExpiringSoon：exp 剩余 < withinSec 秒即视为"将过期/已过期"（无法解析 exp 也按过期处理）
func isExpiringSoon(token string, withinSec int64) bool {
	exp := jwtExp(token)
	if exp == 0 {
		return true
	}
	return exp-time.Now().Unix() < withinSec
}

// ============================== protobuf 微工具（varint / LEN） ==============================

func pbVarint(n uint64) []byte {
	var out []byte
	for n > 0x7f {
		out = append(out, byte(n&0x7f)|0x80)
		n >>= 7
	}
	return append(out, byte(n))
}

func pbBytes(field int, b []byte) []byte {
	out := pbVarint(uint64(field)<<3 | 2)
	out = append(out, pbVarint(uint64(len(b)))...)
	return append(out, b...)
}

func pbStr(field int, s string) []byte { return pbBytes(field, []byte(s)) }

func pbInt(field int, v uint64) []byte {
	out := pbVarint(uint64(field) << 3)
	return append(out, pbVarint(v)...)
}

// PBField：解析后的 protobuf 字段（仅需 varint 与 LEN 两种 wire type）
type PBField struct {
	Fn int
	Wt int
	V  uint64 // wire type 0
	B  []byte // wire type 2
}

func pbReadVarint(b []byte, i int) (uint64, int, error) {
	var v uint64
	var shift uint
	for i < len(b) {
		c := b[i]
		i++
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i, nil
		}
		shift += 7
	}
	return 0, i, errors.New("truncated varint")
}

func pbFields(b []byte) []PBField {
	var fields []PBField
	i := 0
	for i < len(b) {
		tag, ni, err := pbReadVarint(b, i)
		if err != nil {
			break
		}
		i = ni
		fn, wt := int(tag>>3), int(tag&7)
		switch wt {
		case 0:
			v, ni, err := pbReadVarint(b, i)
			if err != nil {
				return fields
			}
			i = ni
			fields = append(fields, PBField{Fn: fn, Wt: wt, V: v})
		case 2:
			ln, ni, err := pbReadVarint(b, i)
			if err != nil {
				return fields
			}
			i = ni
			if i+int(ln) > len(b) {
				return fields
			}
			fields = append(fields, PBField{Fn: fn, Wt: wt, B: b[i : i+int(ln)]})
			i += int(ln)
		case 5:
			fields = append(fields, PBField{Fn: fn, Wt: wt})
			i += 4
		case 1:
			fields = append(fields, PBField{Fn: fn, Wt: wt})
			i += 8
		default:
			return fields
		}
	}
	return fields
}

func pbFind(fields []PBField, fn int) *PBField {
	for i := range fields {
		if fields[i].Fn == fn {
			return &fields[i]
		}
	}
	return nil
}

// frameProto：connect+proto 帧编码 [1B flag][4B BE 长度][payload]
func frameProto(payload []byte) []byte {
	head := make([]byte, 5)
	head[0] = 0
	binary.BigEndian.PutUint32(head[1:], uint32(len(payload)))
	return append(head, payload...)
}

// ============================== 凭据缓存（key = authId） ==============================

type Credential struct {
	AuthID     string    `json:"authId"`
	Token      string    `json:"token"`
	Exp        int64     `json:"exp"`        // unix 秒
	RefreshKey string    `json:"refreshKey"` // 该 authId 用过的刷新凭据（API key）
	UpdatedAt  time.Time `json:"updatedAt"`
}

type flightCall struct {
	ch    chan struct{}
	token string
	err   error
}

type CredStore struct {
	mu     sync.Mutex
	m      map[string]*Credential
	flight map[string]*flightCall
	file   string
}

func newCredStore(file string) *CredStore {
	s := &CredStore{m: map[string]*Credential{}, flight: map[string]*flightCall{}, file: file}
	s.load()
	return s
}

func (s *CredStore) load() {
	if s.file == "" {
		return
	}
	raw, err := os.ReadFile(s.file)
	if err != nil {
		return
	}
	var list []*Credential
	if json.Unmarshal(raw, &list) != nil {
		return
	}
	for _, c := range list {
		if c != nil && c.AuthID != "" {
			s.m[c.AuthID] = c
		}
	}
	log.Printf("[store] 已加载 %d 条凭据缓存 (%s)", len(s.m), s.file)
}

func (s *CredStore) save() {
	if s.file == "" {
		return
	}
	list := make([]*Credential, 0, len(s.m))
	for _, c := range s.m {
		list = append(list, c)
	}
	raw, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(s.file, raw, 0o600)
}

func (s *CredStore) Get(authID string) *Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[authID]
}

func (s *CredStore) Put(c *Credential) {
	s.mu.Lock()
	s.m[c.AuthID] = c
	s.mu.Unlock()
	s.save()
}

func (s *CredStore) all() []*Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Credential, 0, len(s.m))
	for _, c := range s.m {
		out = append(out, c)
	}
	return out
}

// Refresh：用刷新凭据换新 token 并写入缓存（同一 authId single-flight 合并）
func (s *CredStore) Refresh(authID, refreshKey, proxy string) (string, error) {
	s.mu.Lock()
	if fl, ok := s.flight[authID]; ok {
		s.mu.Unlock()
		<-fl.ch
		return fl.token, fl.err
	}
	fl := &flightCall{ch: make(chan struct{})}
	s.flight[authID] = fl
	s.mu.Unlock()

	defer func() {
		close(fl.ch)
		s.mu.Lock()
		delete(s.flight, authID)
		s.mu.Unlock()
	}()

	// 双重检查：排队期间可能已被其他请求刷新
	if c := s.Get(authID); c != nil && !isExpiringSoon(c.Token, 300) {
		fl.token = c.Token
		return fl.token, nil
	}

	r, err := exchangeUserApiKey(refreshKey, proxy)
	if err != nil {
		fl.err = err
		return "", err
	}
	s.Put(&Credential{
		AuthID:     authID,
		Token:      r.AccessToken,
		Exp:        jwtExp(r.AccessToken),
		RefreshKey: refreshKey,
		UpdatedAt:  time.Now(),
	})
	fl.token = r.AccessToken
	log.Printf("[refresh] authId=%s 已刷新，新 token 至 %s", authID, time.Unix(jwtExp(r.AccessToken), 0).Format(time.RFC3339))
	return fl.token, nil
}

var errNeedLogin = errors.New("token 已过期且无可用刷新凭据：请提供 X-Cursor-Api-Key，或调用 /v1/auth/login 重新登录")

// ============================== 透传代理（X-Proxy） ==============================

// proxyFromRequest：从请求头读取上游代理地址（X-Proxy），支持 http / https / socks5
func proxyFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Proxy"))
}

// validateProxy：解析并校验请求头代理；无效时写出 400 并返回 ok=false
func validateProxy(w http.ResponseWriter, r *http.Request) (string, bool) {
	proxy := proxyFromRequest(r)
	if _, err := newProxyTransport(proxy); err != nil {
		writeErr(w, 400, err.Error())
		return "", false
	}
	return proxy, true
}

// newProxyTransport：按代理地址构造 Transport（空串 = 直连）；
// https 目标经 http 代理时自动走 CONNECT 隧道；socks5 用自实现拨号（保持零依赖）
func newProxyTransport(proxy string) (*http.Transport, error) {
	tr := &http.Transport{ForceAttemptHTTP2: true}
	if proxy == "" {
		return tr, nil
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("X-Proxy 代理地址无效: %q", proxy)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5", "socks5h":
		tr.DialContext = socks5DialContext(u.Host)
	default:
		return nil, fmt.Errorf("X-Proxy 不支持的代理协议 %q（支持 http / https / socks5）", u.Scheme)
	}
	return tr, nil
}

// upstreamClient：构造访问 Cursor 上游的 http.Client（timeout=0 表示不限时，用于流式）
func upstreamClient(proxy string, timeout time.Duration) (*http.Client, error) {
	tr, err := newProxyTransport(proxy)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// socks5DialContext：最小 SOCKS5 客户端（RFC 1928，仅 NO AUTH），域名透传（等效 socks5h）
func socks5DialContext(proxyAddr string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 15 * time.Second}
		c, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("连接 SOCKS5 代理失败: %w", err)
		}
		fail := func(e error) (net.Conn, error) {
			c.Close()
			return nil, e
		}
		// 握手：VER=5 NMETHODS=1 NOAUTH
		if _, err := c.Write([]byte{5, 1, 0}); err != nil {
			return fail(err)
		}
		var hs [2]byte
		if _, err := io.ReadFull(c, hs[:]); err != nil {
			return fail(err)
		}
		if hs[0] != 5 || hs[1] != 0 {
			return fail(errors.New("SOCKS5 代理不支持无认证方式"))
		}
		// CONNECT 请求
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return fail(err)
		}
		req := []byte{5, 1, 0}
		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				req = append(req, 1)
				req = append(req, ip4...)
			} else {
				req = append(req, 4)
				req = append(req, ip.To16()...)
			}
		} else {
			req = append(req, 3, byte(len(host)))
			req = append(req, host...)
		}
		port, _ := strconv.Atoi(portStr)
		req = append(req, byte(port>>8), byte(port))
		if _, err := c.Write(req); err != nil {
			return fail(err)
		}
		// 响应：VER REP RSV ATYP BND.ADDR BND.PORT
		var rep [4]byte
		if _, err := io.ReadFull(c, rep[:]); err != nil {
			return fail(err)
		}
		if rep[1] != 0 {
			return fail(fmt.Errorf("SOCKS5 连接目标失败（代码 %d）", rep[1]))
		}
		skip := 0
		switch rep[3] {
		case 1:
			skip = 4
		case 4:
			skip = 16
		case 3:
			var l [1]byte
			if _, err := io.ReadFull(c, l[:]); err != nil {
				return fail(err)
			}
			skip = int(l[0])
		}
		if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
			return fail(err)
		}
		return c, nil
	}
}

// ============================== 鉴权：exchange / 浏览器登录 ==============================

type exchangeResult struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func exchangeUserApiKey(apiKey, proxy string) (*exchangeResult, error) {
	req, _ := http.NewRequest("POST", apiBase+"/auth/exchange_user_api_key", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	cli, cerr := upstreamClient(proxy, 30*time.Second)
	if cerr != nil {
		return nil, cerr
	}
	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("exchange_user_api_key HTTP %d: %s", res.StatusCode, truncate(string(body), 300))
	}
	var r exchangeResult
	if err := json.Unmarshal(body, &r); err != nil || r.AccessToken == "" {
		return nil, fmt.Errorf("exchange 响应异常: %s", truncate(string(body), 300))
	}
	return &r, nil
}

type loginSession struct {
	LoginID   string
	Verifier  string
	UUID      string
	CreatedAt time.Time
	Result    *loginResult
}

type loginResult struct {
	AuthID       string `json:"authId"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
}

type pollResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	AuthID       string `json:"authId"`
	UUID         string `json:"uuid"`
	Challenge    string `json:"challenge"`
}

// pollLoginOnce：对 /auth/poll 做一轮查询
//
//	404 = 登录未完成；403 = 拒绝；200 = 成功返回 token
func pollLoginOnce(loginUUID, verifier, proxy string) (res *pollResponse, pending bool, err error) {
	u := fmt.Sprintf("%s/auth/poll?uuid=%s&verifier=%s", apiBase, url.QueryEscape(loginUUID), url.QueryEscape(verifier))
	cli, cerr := upstreamClient(proxy, 30*time.Second)
	if cerr != nil {
		return nil, false, cerr
	}
	resp, err := cli.Get(u)
	if err != nil {
		return nil, true, nil // 网络抖动按"未完成"处理
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 404:
		return nil, true, nil
	case 403:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, false, fmt.Errorf("登录被拒绝: %s", truncate(string(body), 200))
	case 200:
		var pr pollResponse
		if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil || pr.AccessToken == "" {
			return nil, true, nil
		}
		return &pr, false, nil
	default:
		return nil, true, nil
	}
}

// ============================== Cursor 业务协议 ==============================

// buildRunRequestFrame：AgentClientMessage{ run_request }（裸 payload，由 writeFrame 统一封帧）
func buildRunRequestFrame(prompt, modelID, conversationID string) []byte {
	userMessage := concat(
		pbStr(1, prompt),
		pbStr(2, mustUUID()),
		pbBytes(3, nil),
		pbInt(4, 1),
	)
	action := pbBytes(1, pbBytes(1, userMessage))
	runRequest := concat(
		pbBytes(1, nil),
		pbBytes(2, action),
		pbBytes(4, nil),
		pbStr(5, conversationID),
		pbBytes(9, pbStr(1, modelID)),
		pbInt(12, 0),
		pbStr(16, conversationID),
		pbStr(25, mustUUID()),
	)
	return pbBytes(1, runRequest)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// buildRequestContextReply：ExecClientMessage#10 request_context_result（空上下文即可跑通）
func buildRequestContextReply(execID uint64, hasExec bool) []byte {
	success := pbBytes(1, pbBytes(1, nil))
	execResult := pbBytes(10, success)
	var body []byte
	if hasExec {
		body = concat(pbInt(1, execID), execResult)
	} else {
		body = execResult
	}
	return pbBytes(2, body)
}

// buildMcpStateReply：ExecClientMessage#36 mcp_state_exec_result{ #1:{} } + #39:0
func buildMcpStateReply(execID uint64, hasExec bool) []byte {
	result := pbBytes(36, pbBytes(1, nil))
	parts := [][]byte{result, pbInt(39, 0)}
	if hasExec {
		parts = append([][]byte{pbInt(1, execID)}, parts...)
	}
	return pbBytes(2, concat(parts...))
}

// buildExecControlDone：exec_client_control_message{ #1: { #1: execId } }
func buildExecControlDone(execID uint64, hasExec bool) []byte {
	if hasExec {
		return pbBytes(5, pbBytes(1, pbInt(1, execID)))
	}
	return pbBytes(5, pbBytes(1, nil))
}

// buildKvAck：kv_client_message ack；seq==nil 表示首条序号 0（proto3 省略）
func buildKvAck(seq *uint64) []byte {
	if seq != nil {
		return pbBytes(3, concat(pbInt(1, *seq), pbBytes(3, nil)))
	}
	return pbBytes(3, pbBytes(3, nil))
}

// ============================== Unary HTTP（JSON） ==============================

func makeHeaders(token string, ghost bool) http.Header {
	h := http.Header{}
	h.Set("authorization", "Bearer "+token)
	h.Set("connect-protocol-version", "1")
	h.Set("content-type", "application/json")
	h.Set("accept", "application/json")
	h.Set("x-cursor-client-version", clientVersion)
	h.Set("x-cursor-client-type", "cli")
	if ghost {
		h.Set("x-ghost-mode", "true")
	} else {
		h.Set("x-ghost-mode", "false")
	}
	h.Set("x-request-id", mustUUID())
	return h
}

func unaryCall(base, service, method, token string, ghost bool, proxy string) ([]byte, error) {
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/%s/%s", strings.TrimRight(base, "/"), service, method), strings.NewReader("{}"))
	req.Header = makeHeaders(token, ghost)
	cli, cerr := upstreamClient(proxy, 60*time.Second)
	if cerr != nil {
		return nil, cerr
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s/%s HTTP %d: %s", service, method, resp.StatusCode, truncate(string(body), 300))
	}
	return body, nil
}

// getAgentBase：从 ServerConfig 取 agent 服务地址（ghost 用 agentUrl，普通用 agentnUrl）
func getAgentBase(token string, ghost bool, proxy string) string {
	body, err := unaryCall(apiBase, "aiserver.v1.ServerConfigService", "GetServerConfig", token, ghost, proxy)
	if err != nil {
		log.Printf("[warn] GetServerConfig 失败，回退 %s: %v", apiBase, err)
		return apiBase
	}
	var cfg struct {
		AgentURLConfig struct {
			AgentURL  string `json:"agentUrl"`
			AgentnURL string `json:"agentnUrl"`
		} `json:"agentUrlConfig"`
	}
	if json.Unmarshal(body, &cfg) == nil {
		u := cfg.AgentURLConfig.AgentnURL
		if ghost {
			u = cfg.AgentURLConfig.AgentURL
		}
		if u != "" {
			return u
		}
	}
	return apiBase
}

type ModelEntry struct {
	ModelID        string   `json:"modelId"`
	DisplayModelID string   `json:"displayModelId"`
	DisplayName    string   `json:"displayName"`
	Aliases        []string `json:"aliases"`
}

func getUsableModels(token, agentBase string, ghost bool, proxy string) ([]ModelEntry, error) {
	body, err := unaryCall(agentBase, "agent.v1.AgentService", "GetUsableModels", token, ghost, proxy)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Models []ModelEntry `json:"models"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("解析模型响应失败: %w", err)
	}
	return resp.Models, nil
}

// ============================== 聊天（HTTP/2 全双工 · connect+proto） ==============================

type chatState struct {
	text        strings.Builder
	think       strings.Builder
	turnEnded   bool
	checkpoints int
	onText      func(string)
	onThink     func(string)
}

// handleServerPayload：处理一条 AgentServerMessage
//
//	下行字段：#1 interaction_update | #2 exec_server_message | #3 checkpoint | #4 kv_server_message
func handleServerPayload(payload []byte, send func([]byte), state *chatState) {
	for _, f := range pbFields(payload) {
		switch f.Fn {
		case 1: // interaction_update
			for _, g := range pbFields(f.B) {
				switch g.Fn {
				case 1: // text_delta { #1 text }
					if t := pbFind(pbFields(g.B), 1); t != nil && len(t.B) > 0 {
						s := string(t.B)
						state.text.WriteString(s)
						if state.onText != nil {
							state.onText(s)
						}
					}
				case 4: // thinking_delta { #1 text }
					if t := pbFind(pbFields(g.B), 1); t != nil && len(t.B) > 0 {
						s := string(t.B)
						state.think.WriteString(s)
						if state.onThink != nil {
							state.onThink(s)
						}
					}
				case 14: // turn_ended
					state.turnEnded = true
				}
			}
		case 2: // exec_server_message（服务端要求客户端执行）
			ef := pbFields(f.B)
			idField := pbFind(ef, 1)
			var execID uint64
			hasExec := false
			if idField != nil {
				execID, hasExec = idField.V, true
			}
			switch {
			case pbFind(ef, 10) != nil: // request_context_args
				send(buildRequestContextReply(execID, hasExec))
				send(pbBytes(5, pbBytes(1, nil))) // exec_client_control_message{ #1:{} }
			case pbFind(ef, 36) != nil: // mcp_state_exec_args
				send(buildMcpStateReply(execID, hasExec))
				send(buildExecControlDone(execID, hasExec))
			default:
				if debugTx {
					var fns []int
					for _, x := range ef {
						fns = append(fns, x.Fn)
					}
					log.Printf("[rx] 未处理的 exec_server_message 字段=%v hex=%s", fns, truncate(hex.EncodeToString(f.B), 400))
				}
			}
		case 3: // conversation_checkpoint_update
			state.checkpoints++
		case 4: // kv_server_message → 立即 ack
			if seq := pbFind(pbFields(f.B), 1); seq != nil {
				v := seq.V
				send(buildKvAck(&v))
			} else {
				send(buildKvAck(nil))
			}
		}
	}
}

// chatRun：agent.v1.AgentService/Run（BiDiStreaming），阻塞直至 turnEnded / trailer
func chatRun(ctx context.Context, token, agentBase, prompt, modelID string, ghost bool, proxy string, state *chatState) error {
	u, err := url.Parse(agentBase)
	if err != nil {
		return fmt.Errorf("agent 地址无效: %w", err)
	}
	runURL := fmt.Sprintf("%s://%s/agent.v1.AgentService/Run", u.Scheme, u.Host)

	// 全双工：io.Pipe 作为请求体（持续上传帧），同时读 resp.Body（持续下行帧）。
	// 标准库 http.Transport 在 HTTP/2 下支持同时读写同一流。
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, "POST", runURL, pr)
	if err != nil {
		return err
	}
	reqID := mustUUID()
	trace := fmt.Sprintf("00-%s-%s-01", randHex(16), randHex(8))
	h := req.Header
	h.Set("authorization", "Bearer "+token)
	h.Set("content-type", "application/connect+proto")
	h.Set("connect-protocol-version", "1")
	h.Set("connect-content-encoding", "gzip")
	h.Set("connect-accept-encoding", "gzip,br")
	h.Set("user-agent", "connect-es/1.6.1")
	h.Set("x-cursor-client-version", clientVersion)
	h.Set("x-cursor-client-type", "cli")
	if ghost {
		h.Set("x-ghost-mode", "true")
	} else {
		h.Set("x-ghost-mode", "false")
	}
	h.Set("x-request-id", reqID)
	h.Set("x-original-request-id", reqID)
	h.Set("x-blob-encryption-key", randHex(32))
	h.Set("traceparent", trace)
	h.Set("backend-traceparent", trace)

	var writeMu sync.Mutex
	writeFrame := func(msg []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		frame := frameProto(msg)
		if debugTx {
			log.Printf("[tx] %s", truncate(hex.EncodeToString(frame), 500))
		}
		_, err := pw.Write(frame)
		return err
	}

	// 上行必须与 Do 并行：服务端可能等首帧才回响应头，
	// 若在 Do 返回后才写首帧会造成双向死锁。首帧写入独立 goroutine。
	go func() {
		if err := writeFrame(buildRunRequestFrame(prompt, modelID, mustUUID())); err != nil {
			pw.CloseWithError(err)
		}
	}()

	// 心跳：每 5s AgentClientMessage#7（空 body）；无 ack 回合会挂起
	hbDone := make(chan struct{})
	go func() {
		tk := time.NewTicker(5 * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-ctx.Done():
				return
			case <-tk.C:
				_ = writeFrame(pbBytes(7, nil))
			}
		}
	}()
	defer close(hbDone)
	defer pw.Close() // 结束时给服务端发 END_STREAM

	cli, err := upstreamClient(proxy, 0)
	if err != nil {
		pw.CloseWithError(err)
		return fmt.Errorf("代理配置无效: %w", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		pw.CloseWithError(err)
		return fmt.Errorf("连接 %s 失败: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		pw.CloseWithError(errors.New("bad status"))
		return fmt.Errorf("Run HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// 读循环：connect 帧 = [1B flag][4B BE len][payload]，flag&1=gzip，flag&2=trailer
	head := make([]byte, 5)
	for {
		if _, err := io.ReadFull(resp.Body, head); err != nil {
			if state.turnEnded {
				return nil
			}
			return fmt.Errorf("流结束(未收 turnEnded): %w", err)
		}
		flags := head[0]
		length := binary.BigEndian.Uint32(head[1:])
		if length > 32<<20 {
			return errors.New("帧长度异常")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(resp.Body, payload); err != nil {
			if state.turnEnded {
				return nil
			}
			return fmt.Errorf("读取帧体失败: %w", err)
		}
		if flags&0x01 != 0 { // gzip
			if zr, err := gzip.NewReader(bytes.NewReader(payload)); err == nil {
				if raw, err := io.ReadAll(zr); err == nil {
					payload = raw
				}
				zr.Close()
			}
		}
		if debugTx {
			log.Printf("[rx] flags=%d len=%d %s", flags, length, truncate(hex.EncodeToString(payload), 500))
		}
		if flags&0x02 != 0 { // trailer：流终止
			var tr struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
					Details []struct {
						Debug *struct {
							Error   string `json:"error"`
							Details struct {
								Title  string `json:"title"`
								Detail string `json:"detail"`
							} `json:"details"`
						} `json:"debug"`
					} `json:"details"`
				} `json:"error"`
			}
			if json.Unmarshal(payload, &tr) == nil && tr.Error != nil {
				// 优先使用服务端 debug details 中的可读原因（如免费套餐限制）
				msg := tr.Error.Message
				for _, d := range tr.Error.Details {
					if d.Debug != nil && d.Debug.Details.Detail != "" {
						msg = d.Debug.Details.Detail
						if d.Debug.Details.Title != "" {
							msg = d.Debug.Details.Title + ": " + msg
						}
						break
					}
				}
				return fmt.Errorf("stream error [%s]: %s", tr.Error.Code, msg)
			}
			return nil
		}
		handleServerPayload(payload, func(msg []byte) { _ = writeFrame(msg) }, state)
		if state.turnEnded {
			return nil
		}
	}
}

// ============================== 服务器 ==============================

type agentCacheEntry struct {
	base string
	at   time.Time
}

type Server struct {
	creds     *CredStore
	envAPIKey string
	mu        sync.Mutex
	logins    map[string]*loginSession

	agentMu   sync.Mutex
	agentBase map[string]agentCacheEntry // key: "ghost=true/false"

	modelsMu  sync.Mutex
	modelList map[string]modelCacheEntry // key: "ghost=true/false|authId"
}

func newServer(creds *CredStore) *Server {
	return &Server{
		creds:     creds,
		envAPIKey: os.Getenv("CURSOR_API_KEY"),
		logins:    map[string]*loginSession{},
		agentBase: map[string]agentCacheEntry{},
		modelList: map[string]modelCacheEntry{},
	}
}

func (s *Server) getCachedAgentBase(token string, ghost bool, proxy string) string {
	key := fmt.Sprintf("ghost=%v", ghost)
	s.agentMu.Lock()
	e, ok := s.agentBase[key]
	s.agentMu.Unlock()
	if ok && e.base != "" && time.Since(e.at) < 10*time.Minute {
		return e.base
	}
	base := getAgentBase(token, ghost, proxy)
	s.agentMu.Lock()
	s.agentBase[key] = agentCacheEntry{base: base, at: time.Now()}
	s.agentMu.Unlock()
	return base
}

type modelCacheEntry struct {
	models []ModelEntry
	at     time.Time
}

// getCachedModels：带 10 分钟缓存的模型列表（按账号 + ghost 隔离）
func (s *Server) getCachedModels(token, agentBase string, ghost bool, proxy string) ([]ModelEntry, error) {
	key := fmt.Sprintf("ghost=%v|%s", ghost, jwtSub(token))
	s.modelsMu.Lock()
	e, ok := s.modelList[key]
	s.modelsMu.Unlock()
	if ok && len(e.models) > 0 && time.Since(e.at) < 10*time.Minute {
		return e.models, nil
	}
	models, err := getUsableModels(token, agentBase, ghost, proxy)
	if err != nil {
		return nil, err
	}
	s.modelsMu.Lock()
	s.modelList[key] = modelCacheEntry{models: models, at: time.Now()}
	s.modelsMu.Unlock()
	return models, nil
}

// resolveModelForRun：把 /v1/models 暴露的展示名（displayModelId / alias / modelId）
// 解析为上游 Run 实际接受的 modelId（例如 "auto" → "default"）；
// 匹配不到时原样返回，由上游报错。
func resolveModelForRun(models []ModelEntry, name string) string {
	matches := func(m ModelEntry) bool {
		if m.DisplayModelID == name || m.ModelID == name {
			return true
		}
		for _, a := range m.Aliases {
			if a == name {
				return true
			}
		}
		return false
	}
	for _, m := range models {
		if matches(m) {
			if m.ModelID != "" {
				return m.ModelID
			}
			return name
		}
	}
	return name
}

// resolveToken：核心缓存/刷新逻辑
//  1. 传入 token 未过期 → 直通
//  2. 传入 token 已过期 → 查 authId 缓存：有效的直接用
//  3. 缓存也没有/已过期 → 用刷新凭据（请求头 > 缓存 RefreshKey > env）exchange 换新（single-flight）
//  4. 无刷新凭据 → errNeedLogin
func (s *Server) resolveToken(authID, incoming, headerAPIKey, proxy string) (string, error) {
	if incoming != "" && !isExpiringSoon(incoming, 300) {
		return incoming, nil
	}
	if authID == "" {
		return "", errors.New("缺少 X-Cursor-Auth-Id，且传入 token 已过期/无法解析 sub")
	}
	if c := s.creds.Get(authID); c != nil && !isExpiringSoon(c.Token, 300) {
		return c.Token, nil
	}
	refreshKey := headerAPIKey
	if refreshKey == "" {
		if c := s.creds.Get(authID); c != nil {
			refreshKey = c.RefreshKey
		}
	}
	if refreshKey == "" {
		refreshKey = s.envAPIKey
	}
	if refreshKey == "" {
		return "", errNeedLogin
	}
	return s.creds.Refresh(authID, refreshKey, proxy)
}

// credsFromRequest：从请求头解析鉴权三要素
func (s *Server) credsFromRequest(r *http.Request) (authID, token, apiKey string) {
	ah := r.Header.Get("Authorization")
	if strings.HasPrefix(ah, "Bearer ") {
		token = strings.TrimPrefix(ah, "Bearer ")
	}
	authID = r.Header.Get("X-Cursor-Auth-Id")
	apiKey = r.Header.Get("X-Cursor-Api-Key")
	if authID == "" && token != "" {
		authID = jwtSub(token)
	}
	return
}

// ============================== HTTP 路由处理 ==============================

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": msg, "type": "invalid_request_error"},
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// POST /v1/auth/login → { loginUrl, loginId, expiresIn }
func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	verifier := b64url(randBytes(32))
	ch := sha256.Sum256([]byte(verifier))
	challenge := b64url(ch[:])
	uuidv := mustUUID()

	u, _ := url.Parse(websiteBase + "/loginDeepControl")
	q := u.Query()
	q.Set("challenge", challenge)
	q.Set("uuid", uuidv)
	q.Set("mode", "login")
	q.Set("redirectTarget", "cli")
	u.RawQuery = q.Encode()

	sess := &loginSession{LoginID: uuidv, Verifier: verifier, UUID: uuidv, CreatedAt: time.Now()}
	s.mu.Lock()
	s.logins[uuidv] = sess
	// 清理 10 分钟前的旧会话
	for k, v := range s.logins {
		if time.Since(v.CreatedAt) > 10*time.Minute {
			delete(s.logins, k)
		}
	}
	s.mu.Unlock()

	log.Printf("[login] 新会话 %s", uuidv)
	writeJSON(w, 200, map[string]any{
		"loginUrl":  u.String(),
		"loginId":   uuidv,
		"expiresIn": 600,
	})
}

// GET /v1/auth/login/result?loginId=xxx
//
//	未完成 → 202 {status:"pending"}；完成 → 200 {authId, accessToken, refreshToken, expiresAt}
//	本接口内部最多等待 ~10s（长轮询），调用方可直接循环调用。
func (s *Server) handleLoginResult(w http.ResponseWriter, r *http.Request) {
	proxy, ok := validateProxy(w, r)
	if !ok {
		return
	}
	id := r.URL.Query().Get("loginId")
	s.mu.Lock()
	sess := s.logins[id]
	s.mu.Unlock()
	if sess == nil {
		writeErr(w, 404, "loginId 不存在或已过期，请重新调用 /v1/auth/login")
		return
	}
	if sess.Result != nil {
		writeJSON(w, 200, sess.Result)
		return
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pr, pending, err := pollLoginOnce(sess.UUID, sess.Verifier, proxy)
		if err != nil {
			writeErr(w, 403, err.Error())
			return
		}
		if !pending && pr != nil {
			authID := pr.AuthID
			if authID == "" {
				authID = jwtSub(pr.AccessToken)
			}
			res := &loginResult{
				AuthID:       authID,
				AccessToken:  pr.AccessToken,
				RefreshToken: pr.RefreshToken,
				ExpiresAt:    jwtExp(pr.AccessToken),
			}
			sess.Result = res
			// 登录产物立即进入凭据缓存（后续聊天直接命中）
			s.creds.Put(&Credential{
				AuthID:    authID,
				Token:     pr.AccessToken,
				Exp:       jwtExp(pr.AccessToken),
				UpdatedAt: time.Now(),
			})
			log.Printf("[login] %s 登录成功 authId=%s exp=%s", id, authID, time.Unix(res.ExpiresAt, 0).Format(time.RFC3339))
			writeJSON(w, 200, res)
			return
		}
		time.Sleep(1500 * time.Millisecond)
	}
	writeJSON(w, 202, map[string]any{"status": "pending", "loginId": id})
}

// GET /v1/models
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	proxy, ok := validateProxy(w, r)
	if !ok {
		return
	}
	authID, token, apiKey := s.credsFromRequest(r)
	resolved, err := s.resolveToken(authID, token, apiKey, proxy)
	if err != nil {
		writeErr(w, 401, err.Error())
		return
	}
	ghost := r.URL.Query().Get("ghost") == "true"
	agentBase := s.getCachedAgentBase(resolved, ghost, proxy)
	models, err := s.getCachedModels(resolved, agentBase, ghost, proxy)
	if err != nil {
		writeErr(w, 502, "获取模型列表失败: "+err.Error())
		return
	}
	now := time.Now().Unix()
	seen := map[string]bool{}
	data := []map[string]any{}
	add := func(id, name string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		data = append(data, map[string]any{
			"id": id, "object": "model", "created": now, "owned_by": "cursor",
			"display_name": name,
		})
	}
	for _, m := range models {
		id := m.DisplayModelID
		if id == "" {
			id = m.ModelID
		}
		add(id, m.DisplayName)
		for _, a := range m.Aliases {
			add(a, m.DisplayName)
		}
	}
	writeJSON(w, 200, map[string]any{"object": "list", "data": data})
}

type chatMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func (m chatMessage) text() string {
	var s string
	if json.Unmarshal(m.Content, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(m.Content, &parts) == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Text != "" {
				b.WriteString(p.Text)
			}
		}
		return b.String()
	}
	return ""
}

func messagesToPrompt(msgs []chatMessage) string {
	if len(msgs) == 0 {
		return ""
	}
	if len(msgs) == 1 {
		return msgs[0].text()
	}
	var b strings.Builder
	for i, m := range msgs {
		if i > 0 {
			b.WriteString("\n\n")
		}
		role := "User"
		if m.Role != "" {
			role = strings.ToUpper(m.Role[:1]) + m.Role[1:]
		}
		fmt.Fprintf(&b, "%s: %s", role, m.text())
	}
	return b.String()
}

// POST /v1/chat/completions（OpenAI 兼容；stream=true 时 SSE）
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	proxy, ok := validateProxy(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, 400, "读取请求体失败")
		return
	}
	var req struct {
		Model    string        `json:"model"`
		Messages []chatMessage `json:"messages"`
		Stream   bool          `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "请求体不是合法 JSON: "+err.Error())
		return
	}
	prompt := messagesToPrompt(req.Messages)
	if strings.TrimSpace(prompt) == "" {
		writeErr(w, 400, "messages 为空")
		return
	}
	// requestedModel 用于响应回显；modelID 为实际传给上游的名字（下面归一化）
	requestedModel := req.Model
	if requestedModel == "" {
		requestedModel = "default"
	}
	modelID := requestedModel

	authID, token, apiKey := s.credsFromRequest(r)
	resolved, err := s.resolveToken(authID, token, apiKey, proxy)
	if err != nil {
		writeErr(w, 401, err.Error())
		return
	}
	ghost := r.URL.Query().Get("ghost") == "true"
	agentBase := s.getCachedAgentBase(resolved, ghost, proxy)
	// 模型名归一化：接受 /v1/models 暴露的展示名（如 "auto"），映射为上游 Run 的 modelId（"default"）
	if models, mErr := s.getCachedModels(resolved, agentBase, ghost, proxy); mErr == nil {
		modelID = resolveModelForRun(models, modelID)
	}
	if modelID != requestedModel {
		log.Printf("[chat] 模型名解析: %q → %q", requestedModel, modelID)
	}

	ctx, cancel := context.WithTimeout(r.Context(), defaultTimeout)
	defer cancel()

	completionID := "chatcmpl-" + mustUUID()
	created := time.Now().Unix()

	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fl, _ := w.(http.Flusher)

		sendChunk := func(delta map[string]any, finish any) {
			chunk := map[string]any{
				"id": completionID, "object": "chat.completion.chunk",
				"created": created, "model": requestedModel,
				"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finish}},
			}
			b, _ := json.Marshal(chunk)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if fl != nil {
				fl.Flush()
			}
		}
		sendChunk(map[string]any{"role": "assistant", "content": ""}, nil)

		state := &chatState{onText: func(t string) {
			sendChunk(map[string]any{"content": t}, nil)
		}}
		err := chatRun(ctx, resolved, agentBase, prompt, modelID, ghost, proxy, state)
		if err != nil {
			// 已经开始输出：以 error 事件收尾并给 [DONE]
			b, _ := json.Marshal(map[string]any{"error": map[string]any{"message": err.Error(), "type": "upstream_error"}})
			fmt.Fprintf(w, "data: %s\n\n", b)
		} else {
			sendChunk(map[string]any{}, "stop")
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
		if fl != nil {
			fl.Flush()
		}
		log.Printf("[chat] stream 完成 model=%s out=%dB think=%dB checkpoints=%d turnEnded=%v", modelID, state.text.Len(), state.think.Len(), state.checkpoints, state.turnEnded)
		return
	}

	state := &chatState{}
	err = chatRun(ctx, resolved, agentBase, prompt, modelID, ghost, proxy, state)
	if err != nil {
		writeErr(w, 502, "聊天失败: "+err.Error())
		return
	}
	text := state.text.String()
	writeJSON(w, 200, map[string]any{
		"id": completionID, "object": "chat.completion",
		"created": created, "model": requestedModel,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": text},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     len(prompt) / 4,
			"completion_tokens": len(text) / 4,
			"total_tokens":      (len(prompt) + len(text)) / 4,
		},
	})
	log.Printf("[chat] 完成 model=%s out=%dB turnEnded=%v", modelID, len(text), state.turnEnded)
}

// GET /v1/credentials → 查看缓存中的凭据（authId/过期时间，不返回 token 明文）
func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	list := s.creds.all()
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, map[string]any{
			"authId":    c.AuthID,
			"exp":       c.Exp,
			"expiresAt": time.Unix(c.Exp, 0).Format(time.RFC3339),
			"hasKey":    c.RefreshKey != "",
			"updatedAt": c.UpdatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, 200, map[string]any{"credentials": out})
}

// ============================== main ==============================

func main() {
	port := flag.Int("port", envInt("GATEWAY_PORT", 8787), "监听端口")
	dataFile := flag.String("data", envOr("GATEWAY_DATA", "gateway-credentials.json"), "凭据缓存文件（留空禁用持久化）")
	flag.Parse()

	log.SetFlags(log.LstdFlags)
	log.Printf("cursor-gateway 启动中... (api=%s)", apiBase)

	creds := newCredStore(*dataFile)
	srv := newServer(creds)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/login", srv.handleLoginStart)
	mux.HandleFunc("GET /v1/auth/login/result", srv.handleLoginResult)
	mux.HandleFunc("GET /v1/models", srv.handleModels)
	mux.HandleFunc("POST /v1/chat/completions", srv.handleChatCompletions)
	mux.HandleFunc("GET /v1/credentials", srv.handleCredentials)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "time": time.Now().Format(time.RFC3339)})
	})
	mux.HandleFunc("OPTIONS /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Cursor-Auth-Id, X-Cursor-Api-Key, X-Proxy")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.WriteHeader(204)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("监听 http://%s", addr)
	log.Printf("  1) POST /v1/auth/login          获取授权登录链接")
	log.Printf("  2) GET  /v1/auth/login/result   轮询登录结果（返回 authId + token）")
	log.Printf("  3) GET  /v1/models              模型列表（OpenAI 格式）")
	log.Printf("  4) POST /v1/chat/completions    聊天（OpenAI 兼容，支持 stream）")
	if srv.envAPIKey != "" {
		log.Printf("已配置全局刷新凭据 CURSOR_API_KEY（token 过期时自动 exchange）")
	}
	if err := http.ListenAndServe(addr, logMiddleware(mux)); err != nil {
		log.Fatalf("服务器退出: %v", err)
	}
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(lw, r)
		log.Printf("%s %s → %d (%s)", r.Method, r.URL.Path, lw.status, time.Since(start).Round(time.Millisecond))
	})
}

type loggingWriter struct {
	http.ResponseWriter
	status int
}

func (w *loggingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
