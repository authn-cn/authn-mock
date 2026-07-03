import { describe, expect, it } from 'vitest'
import worker from '../src/index'

const ORIGIN = 'https://mock.test'
async function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(ORIGIN + path, init))
}
function form(data: Record<string, string>): RequestInit {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(data),
  }
}

describe('SAML SP', () => {
  it('serves SP metadata with ACS endpoint', async () => {
    const xml = await (await call('/saml/sp/metadata')).text()
    expect(xml).toContain('SPSSODescriptor')
    expect(xml).toContain(`${ORIGIN}/saml/sp/acs`)
    expect(xml).toContain('WantAssertionsSigned="true"')
  })

  it('SP-initiated login redirects to IdP with a SAMLRequest', async () => {
    const res = await call('/saml/sp/login')
    expect(res.status).toBe(302)
    const loc = new URL(res.headers.get('Location')!)
    expect(loc.pathname).toBe('/saml/idp/sso')
    expect(loc.searchParams.get('SAMLRequest')).toBeTruthy()
  })

  it('end-to-end: IdP-issued Response verifies at SP ACS', async () => {
    const spAcs = `${ORIGIN}/saml/sp/acs`
    const spId = `${ORIGIN}/saml/sp/metadata`
    // IdP 直接签发一个 Response(IdP-initiated 形式)
    const idpRes = await call(
      `/saml/idp/sso?user=alice&acs=${encodeURIComponent(spAcs)}&sp=${encodeURIComponent(spId)}&rid=_req1`,
    )
    const idpForm = await idpRes.text()
    const samlResponse = idpForm.match(/name="SAMLResponse" value="([^"]+)"/)![1]

    // 送到 SP 的 ACS
    const acsRes = await call('/saml/sp/acs', form({ SAMLResponse: samlResponse, RelayState: '/app' }))
    expect(acsRes.status).toBe(200)
    const htmlOut = await acsRes.text()
    expect(htmlOut).toContain('SAML 登录成功')
    expect(htmlOut).toContain('✔ Assertion 签名验证通过')
    expect(htmlOut).toContain('✔ 摘要匹配')
    expect(htmlOut).toContain('alice@mock.authn.example')
    expect(htmlOut).toContain('✔ 与本 SP 匹配')
  })
})

describe('OIDC 资源服务器', () => {
  async function accessToken(scope: string): Promise<string> {
    const res = await call('/oidc/token', form({ grant_type: 'client_credentials', client_id: 'demo', scope }))
    return (await res.json()).access_token
  }

  it('grants access with a valid token carrying the required scope', async () => {
    const res = await call('/rs/api', { headers: { Authorization: `Bearer ${await accessToken('openid profile')}` } })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.message).toContain('成功')
    expect(body.granted_scope).toContain('profile')
  })

  it('rejects missing token with 401', async () => {
    const res = await call('/rs/api')
    expect(res.status).toBe(401)
    expect((await res.json()).error).toBe('invalid_request')
  })

  it('rejects token lacking the required scope with 403', async () => {
    const res = await call('/rs/api', { headers: { Authorization: `Bearer ${await accessToken('openid')}` } })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toBe('insufficient_scope')
  })

  it('rejects a garbage token with 401', async () => {
    const res = await call('/rs/api', { headers: { Authorization: 'Bearer not.a.jwt' } })
    expect(res.status).toBe(401)
    expect((await res.json()).error).toBe('invalid_token')
  })
})
