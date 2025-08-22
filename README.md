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
