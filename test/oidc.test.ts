import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { s256 } from '../src/jwt'

const ORIGIN = 'https://mock.test'

async function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(ORIGIN + path, init))
}

function decodeJwtPayload(token: string): Record<string, unknown> {
  const p = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(Buffer.from(p, 'base64').toString('utf-8'))
}

describe('discovery & jwks', () => {
  it('serves a discovery document with matching issuer', async () => {
    const res = await call('/.well-known/openid-configuration')
    expect(res.status).toBe(200)
    const doc = await res.json()
    expect(doc.issuer).toBe(ORIGIN)
    expect(doc.jwks_uri).toBe(`${ORIGIN}/oidc/jwks.json`)
  })

  it('serves JWKS with an RS256 signing key', async () => {
    const doc = await (await call('/oidc/jwks.json')).json()
    expect(doc.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' })
    expect(doc.keys[0].d).toBeUndefined()
  })
})

describe('authorization code flow with PKCE', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

  async function getCode(extra = ''): Promise<URL> {
    const challenge = await s256(verifier)
    const res = await call(
      '/oidc/authorize?client_id=demo&redirect_uri=https://app.test/cb&response_type=code' +
        `&scope=openid+profile+email+offline_access&state=st1&nonce=n1&user=alice` +
        `&code_challenge=${challenge}&code_challenge_method=S256${extra}`,
    )
    expect(res.status).toBe(302)
    return new URL(res.headers.get('Location')!)
  }

  it('redirects back with code and state', async () => {
    const loc = await getCode()
    expect(loc.origin + loc.pathname).toBe('https://app.test/cb')
    expect(loc.searchParams.get('state')).toBe('st1')
    expect(loc.searchParams.get('code')).toBeTruthy()
  })

  it('exchanges code for tokens and serves userinfo', async () => {
    const code = (await getCode()).searchParams.get('code')!
    const res = await call('/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.test/cb',
        client_id: 'demo',
        code_verifier: verifier,
      }),
    })
    expect(res.status).toBe(200)
    const tokens = await res.json()
    expect(tokens.token_type).toBe('Bearer')
    expect(tokens.refresh_token).toBeTruthy()

    const idClaims = decodeJwtPayload(tokens.id_token)
    expect(idClaims).toMatchObject({
      iss: ORIGIN,
      aud: 'demo',
      sub: 'mock-user-alice',
      nonce: 'n1',
      email: 'alice@mock.authn.example',
    })

    const ui = await call('/oidc/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    })
    expect(ui.status).toBe(200)
    expect(await ui.json()).toMatchObject({ sub: 'mock-user-alice', name: 'Alice Zhang' })
  })

  it('rejects a wrong PKCE verifier', async () => {
    const code = (await getCode()).searchParams.get('code')!
    const res = await call('/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://app.test/cb',
        client_id: 'demo',
        code_verifier: 'wrong-verifier-wrong-verifier-wrong-verifier',
      }),
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe('invalid_grant')
  })

  it('rejects a mismatched redirect_uri', async () => {
    const code = (await getCode()).searchParams.get('code')!
    const res = await call('/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://evil.test/cb',
        client_id: 'demo',
        code_verifier: verifier,
      }),
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe('invalid_grant')
  })

  it('renders the user selection page when user param is absent', async () => {
    const res = await call(
      '/oidc/authorize?client_id=demo&redirect_uri=https://app.test/cb&response_type=code&scope=openid',
    )
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('Alice Zhang')
  })

  it('returns login_required for prompt=none without a user', async () => {
    const res = await call(
      '/oidc/authorize?client_id=demo&redirect_uri=https://app.test/cb&response_type=code&scope=openid&prompt=none',
    )
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('Location')!).searchParams.get('error')).toBe('login_required')
  })
})

describe('other grants', () => {
  it('supports refresh_token grant', async () => {
    const authz = await call(
      '/oidc/authorize?client_id=demo&redirect_uri=https://app.test/cb&response_type=code&scope=openid+offline_access&user=bob',
    )
    const code = new URL(authz.headers.get('Location')!).searchParams.get('code')!
    const first = await (
      await call('/oidc/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: 'https://app.test/cb',
        }),
      })
    ).json()
    const res = await call('/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: first.refresh_token }),
    })
    expect(res.status).toBe(200)
    const tokens = await res.json()
    expect(decodeJwtPayload(tokens.access_token).sub).toBe('mock-user-bob')
  })

  it('supports client_credentials grant', async () => {
    const res = await call('/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'svc-a', scope: 'api' }),
    })
    expect(res.status).toBe(200)
    const tokens = await res.json()
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ sub: 'svc-a', scope: 'api' })
  })

  it('rejects unknown grant types', async () => {
    const res = await call('/oidc/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'password' }),
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toBe('unsupported_grant_type')
  })
})
