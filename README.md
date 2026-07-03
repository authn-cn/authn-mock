# authn-mock

[authn-cn.github.io](https://authn-cn.github.io/) 配套的 **Mock 认证服务**,部署在 Cloudflare Workers 上。当前提供一个功能完整的 **Mock OIDC OP**(OpenID Provider),用于开发联调、集成测试与协议学习。

> ⚠️ **仅供测试**:签名私钥公开在 [src/keys.ts](src/keys.ts) 中,任何人都能伪造本服务签发的令牌。生产系统绝不能信任此服务。

## 端点

| 端点 | 路径 |
|------|------|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/oidc/authorize` |
| Token | `/oidc/token` |
| UserInfo | `/oidc/userinfo` |
| JWKS | `/oidc/jwks.json` |

## 特性

- **零注册**:任意 `client_id` / `redirect_uri` 均被接受,不校验 client secret
- **Authorization Code Flow**,支持 PKCE(S256 / plain)
- `refresh_token`(scope 含 `offline_access` 时签发)与 `client_credentials` grant
- 两个固定测试用户 `alice` / `bob`;授权请求加 `&user=alice` 可跳过选择页(CI 免交互)
- 无状态实现:授权码/令牌都是短时效签名 JWT,无任何存储(因此**授权码不保证单次使用**——这是 mock 与真实 OP 的有意差异)
- CORS 全开,issuer 自动跟随部署域名

## 开发

```bash
npm install
npm test          # vitest(测试直接调用 worker 的 fetch 处理器,覆盖完整授权码流程)
npm run build     # tsc 类型检查 + wrangler dry-run 打包
npm run dev       # 本地 http://localhost:8787
npm run deploy    # 部署到 Cloudflare Workers
```

## 路线图

- [ ] Mock SAML IdP(Metadata / SSO 端点 / 签名 Response)
- [ ] Mock SAML SP(Metadata / ACS 端点,展示解析结果)
- [ ] Mock OIDC RP(向任意 OP 发起登录并逐步展示协议交互)
- [ ] 可配置 claims / token 有效期(URL 参数或每租户隔离)
