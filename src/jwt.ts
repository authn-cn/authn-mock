import { KID, PRIVATE_JWK, PUBLIC_JWK } from './keys'

const ALG = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const

export function b64urlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode(s: string): Uint8Array {
  let t = s.replace(/-/g, '+').replace(/_/g, '/')
  while (t.length % 4) t += '='
  const bin = atob(t)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

let privKeyPromise: Promise<CryptoKey> | null = null
let pubKeyPromise: Promise<CryptoKey> | null = null

function privateKey(): Promise<CryptoKey> {
  privKeyPromise ??= crypto.subtle.importKey('jwk', PRIVATE_JWK, ALG, false, ['sign'])
  return privKeyPromise
}

function publicKey(): Promise<CryptoKey> {
  const { kid, use, ...jwk } = PUBLIC_JWK
  pubKeyPromise ??= crypto.subtle.importKey('jwk', jwk, ALG, false, ['verify'])
  return pubKeyPromise
}

export type Claims = Record<string, unknown>

export async function signJwt(payload: Claims): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid: KID }
  const signingInput =
    b64urlEncode(JSON.stringify(header)) + '.' + b64urlEncode(JSON.stringify(payload))
  const sig = await crypto.subtle.sign(
    ALG,
    await privateKey(),
    new TextEncoder().encode(signingInput),
  )
  return signingInput + '.' + b64urlEncode(new Uint8Array(sig))
}

/** 验证签名与 exp;失败返回 null */
export async function verifyJwt(token: string): Promise<Claims | null> {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const ok = await crypto.subtle.verify(
      ALG,
      await publicKey(),
      b64urlDecode(parts[2]),
      new TextEncoder().encode(parts[0] + '.' + parts[1]),
    )
    if (!ok) return null
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1]))) as Claims
    if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) {
      return null
    }
    return payload
  } catch {
    return null
  }
}

/** PKCE S256: BASE64URL(SHA256(code_verifier)) */
export async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return b64urlEncode(new Uint8Array(digest))
}
