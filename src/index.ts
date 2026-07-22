import { authorize, corsPreflightResponse, discovery, jwks, token, userinfo } from './oidc'
import { idpMetadata, samlSso } from './saml'
import { spMetadata, spLogin, spAcs, spHome } from './saml-sp'
import { rpHome, rpStart, rpCallback } from './rp'
import { rsApi, rsHome } from './rs'
import { totpHome, totpCode, totpVerify } from './totp'
import { waHome, waRegisterOptions, waRegisterVerify, waLoginOptions, waLoginVerify } from './webauthn'
import { d1Store, handleMail, receiveEmail } from './mail'
import { ldapHome, ldapEntries, ldapSearch } from './ldap'
import {
  wxLoginJs,
  qrconnect,
  poll,
  scan,
  snsAccessToken,
  snsRefreshToken,
  snsUserinfo,
  snsAuth,
  wechatHome,
  wechatCallback,
  d1TicketStore,
  memTicketStore,
  type TicketStore,
} from './wechat'
import {
  wwLoginJs,
  qrConnect,
  scan as wecomScan,
  gettoken,
  authGetUserInfo,
  userGet,
  getUserDetail,
  wecomHome,
  wecomCallback,
} from './wecom'
import { homePage } from './html'

export interface Env {
  DB: D1Database
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)
    const issuer = url.origin

    // 微信扫码会话存储:有 D1 绑定用 D1(生产,跨 isolate 持久),否则内存回退(测试)。
    const wechatTickets = (): TicketStore =>
      env?.DB ? d1TicketStore(env.DB) : memTicketStore()

    if (req.method === 'OPTIONS') return corsPreflightResponse()

    // Mock 邮件服务器(/mail/*)
    if (url.pathname === '/mail' || url.pathname.startsWith('/mail/')) {
      const res = await handleMail(req, url, d1Store(env.DB))
      if (res) return res
    }

    switch (url.pathname) {
      case '/':
        return new Response(homePage(issuer), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })

      // OIDC OP
      case '/.well-known/openid-configuration':
        return discovery(issuer)
      case '/oidc/jwks.json':
        return jwks()
      case '/oidc/authorize':
        return authorize(req, issuer)
      case '/oidc/token':
        return token(req, issuer)
      case '/oidc/userinfo':
        return userinfo(req)

      // SAML IdP
      case '/saml/idp/metadata':
        return idpMetadata(issuer)
      case '/saml/idp/sso':
        return samlSso(req, issuer)

      // SAML SP(服务提供方)
      case '/saml/sp/':
      case '/saml/sp':
        return spHome(issuer)
      case '/saml/sp/metadata':
        return spMetadata(issuer)
      case '/saml/sp/login':
        return spLogin(req, issuer)
      case '/saml/sp/acs':
        return spAcs(req, issuer)

      // OIDC RP(客户端,连接外部 OP)
      case '/rp/':
      case '/rp':
        return rpHome(issuer)
      case '/rp/start':
        return rpStart(req, issuer)
      case '/rp/callback':
        return rpCallback(req)

      // OIDC/OAuth2 资源服务器
      case '/rs/':
      case '/rs':
        return rsHome(issuer)
      case '/rs/api':
        return rsApi(req)

      // TOTP 验证器
      case '/totp/':
      case '/totp':
        return totpHome(issuer)
      case '/totp/code':
        return totpCode(req)
      case '/totp/verify':
        return totpVerify(req)

      // WebAuthn RP
      case '/webauthn/':
      case '/webauthn':
        return waHome()
      case '/webauthn/register/options':
        return waRegisterOptions(req)
      case '/webauthn/register/verify':
        return waRegisterVerify(req)
      case '/webauthn/login/options':
        return waLoginOptions(req)
      case '/webauthn/login/verify':
        return waLoginVerify(req)

      // Mock 微信扫码登录(网站应用)——与官方同参数/同响应,仅域名不同
      case '/wechat':
      case '/wechat/':
        return wechatHome(issuer)
      case '/wechat/wxLogin.js':
        return wxLoginJs(issuer)
      case '/wechat/callback':
        return wechatCallback(req, issuer)
      case '/wechat/scan':
        return scan(req, wechatTickets())
      case '/connect/qrconnect':
        return qrconnect(req, issuer, wechatTickets())
      case '/connect/poll':
        return poll(req, wechatTickets())
      case '/sns/oauth2/access_token':
        return snsAccessToken(req)
      case '/sns/oauth2/refresh_token':
        return snsRefreshToken(req)
      case '/sns/userinfo':
        return snsUserinfo(req)
      case '/sns/auth':
        return snsAuth(req)

      // Mock 企业微信(WeCom)扫码登录——所有端点收敛在 /wecom 下,与官方同参数/同响应
      case '/wecom':
      case '/wecom/':
        return wecomHome(issuer)
      case '/wecom/wwLogin.js':
        return wwLoginJs(issuer)
      case '/wecom/callback':
        return wecomCallback(req, issuer)
      case '/wecom/scan':
        return wecomScan(req, wechatTickets())
      case '/wecom/sso/qrConnect':
        return qrConnect(req, issuer, wechatTickets())
      case '/wecom/sso/poll':
        return poll(req, wechatTickets())
      case '/wecom/cgi-bin/gettoken':
        return gettoken(req)
      case '/wecom/cgi-bin/auth/getuserinfo':
        return authGetUserInfo(req)
      case '/wecom/cgi-bin/user/get':
        return userGet(req)
      case '/wecom/cgi-bin/auth/getuserdetail':
        return getUserDetail(req)

      // LDAP 目录搜索模拟器
      case '/ldap/':
      case '/ldap':
        return ldapHome(issuer)
      case '/ldap/entries':
        return ldapEntries()
      case '/ldap/search':
        return ldapSearch(req)

      default:
        return new Response('Not Found', { status: 404 })
    }
  },

  // Cloudflare Email Routing 把投递到本 Worker 的邮件送到这里,写入 Mock 收件箱(D1)。
  async email(message: ForwardableEmailMessage, env: Env): Promise<void> {
    await receiveEmail(message, d1Store(env.DB))
  },
} satisfies ExportedHandler<Env>
