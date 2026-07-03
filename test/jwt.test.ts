import { describe, expect, it } from 'vitest'
import { b64urlDecode, b64urlEncode, s256, signJwt, verifyJwt } from '../src/jwt'

describe('b64url', () => {
  it('roundtrips utf-8 strings', () => {
    const s = '你好 authn ±§'
    expect(new TextDecoder().decode(b64urlDecode(b64urlEncode(s)))).toBe(s)
  })
})

describe('signJwt / verifyJwt', () => {
  it('signs and verifies a payload', async () => {
    const exp = Math.floor(Date.now() / 1000) + 60
    const token = await signJwt({ sub: 'u1', exp })
    const payload = await verifyJwt(token)
    expect(payload).toMatchObject({ sub: 'u1', exp })
  })

  it('rejects expired tokens', async () => {
    const token = await signJwt({ sub: 'u1', exp: Math.floor(Date.now() / 1000) - 10 })
    expect(await verifyJwt(token)).toBeNull()
  })

  it('rejects tampered tokens', async () => {
    const token = await signJwt({ sub: 'u1', exp: Math.floor(Date.now() / 1000) + 60 })
    const [h, p, sig] = token.split('.')
    const forged = JSON.parse(new TextDecoder().decode(b64urlDecode(p)))
    forged.sub = 'admin'
    expect(await verifyJwt(`${h}.${b64urlEncode(JSON.stringify(forged))}.${sig}`)).toBeNull()
  })
})

describe('PKCE S256', () => {
  it('matches the RFC 7636 appendix B test vector', async () => {
    expect(await s256('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    )
  })
})
