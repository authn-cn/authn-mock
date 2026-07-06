import { authorize, corsPreflightResponse, discovery, jwks, token, userinfo } from './oidc'
import { idpMetadata, samlSso } from './saml'
import { spMetadata, spLogin, spAcs, spHome } from './saml-sp'
import { rpHome, rpStart, rpCallback } from './rp'
import { rsApi, rsHome } from './rs'
import { totpHome, totpCode, totpVerify } from './totp'
import { waHome, waRegisterOptions, waRegisterVerify, waLoginOptions, waLoginVerify } from './webauthn'
import { d1Store, handleMail, receiveEmail } from './mail'
import { ldapHome, ldapEntries, ldapSearch } from './ldap'
import { homePage } from './html'

export interface Env {
  DB: D1Database
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url)
    const issuer = url.origin

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
