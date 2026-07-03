import { authorize, corsPreflightResponse, discovery, jwks, token, userinfo } from './oidc'
import { homePage } from './html'

export default {
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)
    const issuer = url.origin

    if (req.method === 'OPTIONS') return corsPreflightResponse()

    switch (url.pathname) {
      case '/':
        return new Response(homePage(issuer), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        })
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
      default:
        return new Response('Not Found', { status: 404 })
    }
  },
} satisfies ExportedHandler
