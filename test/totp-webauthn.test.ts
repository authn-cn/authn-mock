import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { totpAt } from '../src/totp'
import { cborDecode, derToRawEcdsa } from '../src/webauthn'

const ORIGIN = 'https://mock.test'
async function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(ORIGIN + path, init))
}

// RFC 6238 测试密钥:ASCII "12345678901234567890" 的 Base32
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'

describe('TOTP (RFC 6238 官方向量)', () => {
  it('SHA1 8 位在给定时间产出规范值', async () => {
    expect(await totpAt(RFC_SECRET, 59, { digits: 8 })).toBe('94287082')
    expect(await totpAt(RFC_SECRET, 1111111109, { digits: 8 })).toBe('07081804')
    expect(await totpAt(RFC_SECRET, 1234567890, { digits: 8 })).toBe('89005924')
  })

  it('/totp/code 返回当前码,/totp/verify 校验它', async () => {
    const secret = 'JBSWY3DPEHPK3PXP'
    const codeRes = await (await call(`/totp/code?secret=${secret}`)).json()
    expect(codeRes.code).toMatch(/^\d{6}$/)
    const verifyRes = await (
      await call('/totp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, code: codeRes.code }),
      })
    ).json()
    expect(verifyRes.valid).toBe(true)
  })

  it('拒绝错误的验证码', async () => {
    const res = await (
      await call('/totp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret: 'JBSWY3DPEHPK3PXP', code: '000000', window: 0 }),
      })
    ).json()
    expect(res.valid).toBe(false)
  })
})

describe('WebAuthn 辅助函数', () => {
  it('CBOR 解码 map / bytes / 负整数键(COSE 风格)', () => {
    // {1: 2, 3: -7, -1: h'0102'} → EC2/ES256/crv 风格
    const buf = new Uint8Array([0xa3, 0x01, 0x02, 0x03, 0x26, 0x20, 0x42, 0x01, 0x02])
    const m = cborDecode(buf).value as Map<number, unknown>
    expect(m.get(1)).toBe(2)
    expect(m.get(3)).toBe(-7)
    expect(Array.from(m.get(-1) as Uint8Array)).toEqual([1, 2])
  })

  it('ECDSA DER→raw:与 WebCrypto 原始签名一致', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const data = new TextEncoder().encode('hello')
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data))
    // 把 raw r||s 编成 DER,再用 derToRawEcdsa 还原,应等于原 raw
    const der = rawToDer(raw)
    const back = derToRawEcdsa(der)
    expect(Array.from(back)).toEqual(Array.from(raw))
    // 且还原后的 raw 能通过验证
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, back, data)
    expect(ok).toBe(true)
  })
})

describe('WebAuthn 端点', () => {
  it('注册 options 返回合法结构与 challenge cookie', async () => {
    const res = await call('/webauthn/register/options', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice' }),
    })
    const opt = await res.json()
    expect(opt.rp.id).toBe('mock.test')
    expect(opt.challenge).toBeTruthy()
    expect(opt.pubKeyCredParams.some((p: any) => p.alg === -7)).toBe(true)
    expect(res.headers.get('Set-Cookie')).toContain('authn_wa_chal=')
  })

  it('未注册时登录 options 报错', async () => {
    const res = await call('/webauthn/login/options', { method: 'POST' })
    expect(res.status).toBe(400)
  })
})

// 测试辅助:raw r||s(64B)→ DER SEQ{INTEGER r, INTEGER s}
function rawToDer(raw: Uint8Array): Uint8Array {
  const enc = (b: Uint8Array) => {
    let i = 0
    while (i < b.length - 1 && b[i] === 0) i++
    let v = b.slice(i)
    if (v[0] & 0x80) v = new Uint8Array([0, ...v])
    return new Uint8Array([0x02, v.length, ...v])
  }
  const r = enc(raw.slice(0, 32))
  const s = enc(raw.slice(32, 64))
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s])
}
