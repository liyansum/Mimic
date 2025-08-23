# Mimic Proxy

Mimic 是一个基于 **HTTP/2 + TLS** 的代理协议。  

---

### 基础特性
- **传输层**：TLS 1.2/1.3，强制 HTTPS  
- **会话层**：HTTP/2 多路复用，每个 SOCKS5 连接映射为单独的 HTTP/2 stream  
- **鉴权方式**：HTTP Header 携带 `X-Auth: <password>`，失败时统一返回站点的正常回退内容（例如 404 或 fallback 页面）  
- **伪装行为**：
  - 未带鉴权访问 `/proxy/*` → 永远返回 `404 Not Found` 或 fallback 内容
  - 其他 URL → 始终代理到 `fallback_addr`（例如真实网站）  
- **加密**：依赖 TLS，不额外加密  

### 端点定义
- **TCP 隧道**：`POST /proxy/tunnel`
  - Header：
    - `X-Auth: <password>`
    - `X-Target-Host: example.com`
    - `X-Target-Port: 443`
  - Body 双向透传目标 TCP 流  
- **UDP 映射**：`POST /proxy/udp`
  - Header：
    - `X-Auth: <password>`
  - Body：
    ```json
    {
      "Host": "8.8.8.8",
      "Port": 53,
      "Data": "<base64 packet>"
    }
    ```
  - 响应：目标返回的 UDP 数据  

---


## 特性

- **隐匿性**：外部观察者只会看到一次普通 HTTPS 访问
- **HTTP/2 多路复用**：大量 TCP/UDP 请求复用同一个 TLS 会话
- **UDP 支持**：支持 DNS、QUIC 等基于 UDP 的协议
- **健康检查**：超时自动关闭，避免阻塞
- **回退模式**：Server 可配置 fallback_addr，对未授权访问返回正常页面

## 配置说明

服务端配置 (TOML 格式)

```toml
listen = ":443"                 # 监听地址
domain = "yourdomain.com"       # 期望的 TLS SNI (可选，用于验证)
cert_file = "server.crt"        # TLS 证书文件
key_file = "server.key"         # TLS 私钥文件
auth_password = "your_password" # 认证密码
fallback = "127.0.0.1:8080"     # 回退代理地址 (可选，用于非代理请求)
read_timeout_sec = 15           # 读超时
write_timeout_sec = 15          # 写超时
idle_timeout_sec = 60           # HTTP 连接空闲超时
max_http2_streams = 250         # 最大并发 HTTP/2 流数
udp_session_idle_sec = 120      # UDP 会话空闲超时
```

## 客户端配置 (TOML 格式)

```toml
server = "yourdomain.com:443"   # 服务端地址
password = "your_password"      # 认证密码
socks5_listen = "127.0.0.1:1080" # 本地 SOCKS5 监听地址
verify_cert = true              # 是否验证服务端 TLS 证书
max_concurrent_streams = 200    # 限制并发流数 (客户端级)
connect_retry = 3               # TCP 连接重试次数
```

## 安全与认证

· 传输安全：所有通信均受 TLS 1.2/1.3 保护。
· 认证：通过 X-Auth-Password HTTP 头进行简单密码认证。确保使用强密码。
· SNI 验证（可选）：服务端可配置验证 TLS 握手中的 SNI 字段，阻止非法域名的连接。
