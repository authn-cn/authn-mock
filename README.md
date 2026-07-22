# authn-mock

[authn-cn.pages.dev](https://authn-cn.pages.dev/) 配套的 **Mock 认证服务**,部署在 Cloudflare Workers 上。当前提供一个功能完整的 **Mock OIDC OP**(OpenID Provider),用于开发联调、集成测试与协议学习。

> ⚠️ **仅供测试**:签名私钥公开在 [src/keys.ts](src/keys.ts) 中,任何人都能伪造本服务签发的令牌。生产系统绝不能信任此服务。

## 端点

| 端点 | 路径 |
|------|------|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/oidc/authorize` |
| Token | `/oidc/token` |
| UserInfo | `/oidc/userinfo` |
| JWKS | `/oidc/jwks.json` |

## Mock 微信扫码登录(网站应用)

除了 OIDC OP,本服务还提供一个 **Mock 微信开放平台"网站应用"扫码登录**:与微信官方**输入输出完全一致,只是域名不同**——同名的 `WxLogin` JS SDK、相同的授权回跳 `redirect_uri?code=&state=`、相同的 `/sns/*` 接口路径与响应字段。扫码环节也跳转到本 mock,确认后返回一个**固定测试用户**。

| 端点 | 路径 | 对应微信官方 |
|------|------|-------------|
| JS SDK | `/wechat/wxLogin.js` | `res.wx.qq.com/.../wxLogin.js` |
| 内嵌二维码页 | `/connect/qrconnect` | `open.weixin.qq.com/connect/qrconnect` |
| code 换 token | `/sns/oauth2/access_token` | `api.weixin.qq.com/sns/oauth2/access_token` |
| 刷新 token | `/sns/oauth2/refresh_token` | `api.weixin.qq.com/sns/oauth2/refresh_token` |
| 用户信息 | `/sns/userinfo` | `api.weixin.qq.com/sns/userinfo` |
| 校验 token | `/sns/auth` | `api.weixin.qq.com/sns/auth` |
| 控制台 / 自演示 | `/wechat/` | — |

接入方式与官方一致:

```html
<div id="login_container"></div>
<script src="https://<你的部署域名>/wechat/wxLogin.js"></script>
<script>
  new WxLogin({
    id: "login_container",
    appid: "你的_appid",
    scope: "snsapi_login",
    redirect_uri: "https://your-app.example/callback",
    state: "任意防伪串"
  });
</script>
```

用户扫码(或在扫码页点"模拟扫码"→"确认登录")后回跳 `redirect_uri?code=&state=`,后端拿 `code` 走:

```bash
curl "https://<域名>/sns/oauth2/access_token?appid=demo&secret=x&code=<CODE>&grant_type=authorization_code"
# → { access_token, expires_in, refresh_token, openid, scope, unionid }
curl "https://<域名>/sns/userinfo?access_token=<AT>&openid=<OPENID>"
# → { openid, nickname, sex, province, city, country, headimgurl, privilege, unionid }
```

> 扫码会话(ticket)落库 **D1**(表 `wechat_tickets`,见 `migrations/0002_wechat_tickets.sql`),因此跨 isolate/跨请求稳定,支持真机扫码;`code`/`access_token`/`refresh_token` 仍是短时效签名 JWT,过期会话自净。首次部署或本地开发需先建表:`npx wrangler d1 migrations apply authn-mock-mail`(本地加 `--local`)。

## Mock 企业微信扫码登录(WeCom)

与企业微信官方网页扫码登录**输入输出一致**——同名 `WwLogin` JS SDK、相同回跳 `redirect_uri?code=&state=`。所有端点收敛在 **`/wecom`** 下(把官方 base URL 换成 `<本站>/wecom` 即可)。取用户信息按企业微信规范**分三步**(access_token 是"应用级"令牌,单独获取,不随 code 一起返回):

| 步骤 / 端点 | 路径 | 对应企业微信官方 |
|------|------|-------------|
| JS SDK | `/wecom/wwLogin.js` | `wwcdn.weixin.qq.com/.../wwLogin-*.js` |
| 内嵌二维码页 | `/wecom/sso/qrConnect` | `open.work.weixin.qq.com/wwopen/sso/qrConnect` |
| ① 取 access_token | `/wecom/cgi-bin/gettoken` | `qyapi.weixin.qq.com/cgi-bin/gettoken` |
| ② code 换 userid | `/wecom/cgi-bin/auth/getuserinfo` | `qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo` |
| ③ 查成员详情 | `/wecom/cgi-bin/user/get` | `qyapi.weixin.qq.com/cgi-bin/user/get` |
| (可选)敏感信息 | `/wecom/cgi-bin/auth/getuserdetail` | `qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail` |
| 控制台 / 自演示 | `/wecom/` | — |

```html
<div id="ww_login"></div>
<script src="https://<你的部署域名>/wecom/wwLogin.js"></script>
<script>
  new WwLogin({
    id: "ww_login",
    appid: "你的_corpid",
    agentid: "你的_agentid",
    redirect_uri: "https://your-app.example/callback",
    state: "任意防伪串"
  });
</script>
```

新版 `@wecom/jssdk` 的 `ww.createWWLoginPanel({ params: { login_type:"CorpApp", appid, agentid, redirect_uri, state } })` 指向同一套 qrConnect 与 `cgi-bin/*` 接口,把 base URL 换成 `<本站>/wecom` 即可。扫码确认后:

```bash
curl "https://<域名>/wecom/cgi-bin/gettoken?corpid=demo&corpsecret=x"
# → { errcode:0, access_token, expires_in }
curl "https://<域名>/wecom/cgi-bin/auth/getuserinfo?access_token=<AT>&code=<CODE>"
# → { errcode:0, userid, user_ticket }
curl "https://<域名>/wecom/cgi-bin/user/get?access_token=<AT>&userid=<USERID>"
# → { errcode:0, userid, name, department, mobile, email, ... }
```

## 从 Mock 切换到真实(只改「引入的 JS」与「URL」)

Mock 的 SDK 与官方逐字节一致(`redirect_uri` 不做 `encodeURIComponent`,按官方约定由调用方 urlencode),且**不校验 appid/secret/corpid 等凭据的值**(微信侧完全不看;企业微信侧仅按官方约定检查 corpid/corpsecret 是否存在)。因此上线时业务代码一行不用改,只需替换下面两处:

**微信开放平台(网站应用)**

| 改什么 | Mock | 真实 |
|--------|------|------|
| 引入的 JS | `https://<域名>/wechat/wxLogin.js` | `https://res.wx.qq.com/connect/zh_CN/htmledition/js/wxLogin.js` |
| 后端 API base | `https://<域名>` | `https://api.weixin.qq.com` |

后端路径不变:`/sns/oauth2/access_token`、`/sns/userinfo` …；`new WxLogin({...})` 参数、回跳 `redirect_uri?code=&state=`、各接口字段均一致。

**企业微信(WeCom)**

| 改什么 | Mock | 真实 |
|--------|------|------|
| 引入的 JS | `https://<域名>/wecom/wwLogin.js` | 官方 `wwLogin` CDN 或 `@wecom/jssdk` |
| 后端 API base | `https://<域名>/wecom` | `https://qyapi.weixin.qq.com` |

后端路径不变:`/cgi-bin/gettoken`、`/cgi-bin/auth/getuserinfo`、`/cgi-bin/user/get` …；`new WwLogin({...})` 参数与各接口字段均一致。

> 有意保留的差异(不影响切换):Mock 的授权 `code`/`access_token` 是短时效自签 JWT,**授权码可重复使用、且固定返回一个用户**(微信 `openid`、企微 `userid=zhangsan`)。切到真实后由真实服务发码,自然消失。
>
> 在线介绍与端到端演示见文档站:[微信扫码登录](https://authn-cn.pages.dev/cn-sso/wechat.html) · [企业微信扫码登录](https://authn-cn.pages.dev/cn-sso/wecom.html)。

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
