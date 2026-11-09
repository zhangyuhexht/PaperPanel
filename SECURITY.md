# 安全部署说明

PaperPanel 是一个**能直接在服务器上执行任意控制台指令**的后台面板。它的权限等价于服务器控制台，因此部署时必须按"最高权限入口"来对待，而不是当成一个普通网页。

## 上线前检查清单

- [ ] 修改默认密码 `change-me-123`（`paper-panel/config.json` 或 `plugins/PaperPanel/config.yml`），使用足够长的随机密码
- [ ] 启用 HTTPS：独立版填 `tls.certFile` / `tls.keyFile`；插件版置于反向代理之后
- [ ] 不要把 52369 直接暴露到公网，优先用防火墙 / 安全组限制来源 IP，或只监听 `127.0.0.1` 走 SSH 隧道
- [ ] 确认 Node 版与插件版没有同时占用 52369
- [ ] 不要把 `config.json` / `plugins/PaperPanel/config.yml` 提交到任何公开仓库或贴进截图
- [ ] 定期检查服务器日志中是否有异常登录失败记录

## 认证链路

```
浏览器                                       服务端
  |  GET /api/nonce                            |
  |------------------------------------------->|  生成 16 字节随机 nonce，2 分钟有效
  |<-------------------------------------------|
  |  用户输入密码（仅存在于内存中的输入框）      |
  |  inner = SHA256(password)                  |
  |  digest = SHA256(nonce + ":" + inner)      |
  |  POST /api/login { nonce, digest }         |
  |------------------------------------------->|  消费 nonce（一次性）
  |                                            |  用恒定时间比较 digest 与期望值
  |<-------------------------------------------|  成功返回 32 字节随机会话令牌
  |  Authorization: Bearer <token>             |
  |------------------------------------------->|  内存校验，过期 / 登出即失效
```

- 明文密码**不上网络、不进 localStorage / sessionStorage / Cookie、不写进 JS 源码**
- 校验值用一次性 nonce 绑定，抓包重放无效
- 会话令牌只在内存中，进程重启或页面刷新都需重新输密码
- 失败 8 次锁定 300 秒（按 IP 计数，`login-max-fails` / `login-lock-seconds` 可配）

> 挑战应答能防明文窃听与重放，但**无法替代 HTTPS**：没有 TLS 时，会话令牌本身仍可能被截获。生产环境务必加密传输。

## 建议的反向代理配置（插件版）

插件本身只监听 HTTP，用 Nginx 终止 TLS 并转发：

```nginx
server {
    listen 443 ssl http2;
    server_name panel.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    # 可选：再套一层来源限制
    # allow 192.168.1.0/24;
    # deny  all;

    location / {
        proxy_pass http://127.0.0.1:52369;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Connection "";
        proxy_buffering off;       # SSE 必须关闭缓冲
        proxy_read_timeout 3600s;  # 长连接保活
        proxy_cache off;
    }
}
```

`proxy_buffering off` 是关键：开启缓冲会导致控制台日志卡住不刷新。若还有一层 CDN / 网关，同样需要禁用对 `text/event-stream` 的缓冲。

插件的 `config.yml` 中建议把 `host` 改成 `127.0.0.1`，让面板只接受本机反代流量。

## 已实现的防护边界

| 层面 | 措施 |
| --- | --- |
| 传输 | 独立版支持内置 TLS；插件版建议反代 TLS；全站 `Cache-Control: no-store` |
| 认证 | nonce + SHA-256 校验值、恒定时间比较、防重放、内存令牌、失败锁定 |
| 浏览器 | CSP `default-src 'none'` 且脚本样式仅 `'self'`、禁止内联与外链、`frame-ancestors 'none'`、禁用嵌入、限制权限策略 |
| 服务端 | 静态资源白名单（禁止目录穿越与读取配置）、请求体与指令长度上限、除 `nonce`/`login`/`logout` 外全部接口强制鉴权 |
| 指令 | 危险指令前端二次确认；插件版指令在主线程调度执行，避免跨线程调用 Bukkit API |

## 已知边界

- 面板**没有**做多用户、权限分级、操作审计日志；它假定"能登录的人 = 服务器管理员"
- 暴力破解锁定是**单进程内存按 IP 计数**，多实例或重启后计数清零；公网部署请在反代 / 防火墙层再限流
- 前端确认只是防误触，不是安全边界：任何持有有效令牌的请求都可直接调用指令接口
- 日志流会把服务器后台原文推送给已登录者，其中可能包含玩家 IP、插件密钥等内容，请勿把面板账号分享给不信任的人

## 报告漏洞

请不要在公开 Issue 里贴可利用细节。优先通过仓库的 **Security → Report a vulnerability**（私有漏洞报告）提交；若未开启，可先开一个不含细节的 Issue 索取联系方式。
