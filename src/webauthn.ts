/**
 * Mock WebAuthn RP(依赖方 / Relying Party),自包含注册 + 登录演示。
 * 因为 WebAuthn 的 rpId 必须匹配调用页面所在域,本 RP 自带一个演示页面
 * (与端点同域),可在浏览器里完整跑通 Passkey 注册与登录,并做真实的断言验签。
 *
 * 端点:
 *   GET  /webauthn/                 —— 自包含演示页(注册 / 登录 Passkey)
 *   POST /webauthn/register/options —— 生成 PublicKeyCredentialCreationOptions
 *   POST /webauthn/register/verify  —— 解析 attestation,存下 credential 公钥
 *   POST /webauthn/login/options    —— 生成 PublicKeyCredentialRequestOptions
 *   POST /webauthn/login/verify     —— 用已存公钥验证断言签名
 *
 * 无状态:challenge 与已注册 credential 打包进签名 JWT,存 HttpOnly cookie。仅供测试。
 */
import { signJwt, verifyJwt, b64urlDecode } from './jwt'

const CHAL_COOKIE = 'authn_wa_chal'
const CRED_COOKIE = 'authn_wa_cred'

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  })
}
function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function readCookie(req: Request, name: string): string | null {
  const h = req.headers.get('Cookie')
  if (!h) return null
  for (const part of h.split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k === name) return v.join('=')
  }
  return null
}
async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

// -------------------------------------------------------------------------
// 最小 CBOR 解码(够解析 attestationObject 与 COSE key)
// -------------------------------------------------------------------------
export function cborDecode(buf: Uint8Array, pos = 0): { value: unknown; pos: number } {
  const first = buf[pos++]
  const major = first >> 5
  const info = first & 0x1f
  let len = info
  if (info === 24) len = buf[pos++]
  else if (info === 25) { len = (buf[pos] << 8) | buf[pos + 1]; pos += 2 }
  else if (info === 26) { len = ((buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]) >>> 0; pos += 4 }
  else if (info === 27) { const hi = ((buf[pos] << 24) | (buf[pos + 1] << 16) | (buf[pos + 2] << 8) | buf[pos + 3]) >>> 0; const lo = ((buf[pos + 4] << 24) | (buf[pos + 5] << 16) | (buf[pos + 6] << 8) | buf[pos + 7]) >>> 0; len = hi * 0x100000000 + lo; pos += 8 }

  switch (major) {
    case 0: return { value: len, pos }
    case 1: return { value: -1 - len, pos }
    case 2: return { value: buf.slice(pos, pos + len), pos: pos + len }
    case 3: return { value: new TextDecoder().decode(buf.slice(pos, pos + len)), pos: pos + len }
    case 4: {
      const arr: unknown[] = []
      for (let i = 0; i < len; i++) { const r = cborDecode(buf, pos); arr.push(r.value); pos = r.pos }
      return { value: arr, pos }
    }
    case 5: {
      const map = new Map<unknown, unknown>()
      for (let i = 0; i < len; i++) {
        const k = cborDecode(buf, pos); pos = k.pos
        const v = cborDecode(buf, pos); pos = v.pos
        map.set(k.value, v.value)
      }
      return { value: map, pos }
    }
    default: return { value: null, pos }
  }
}

// COSE key(Map)→ JWK(仅公钥)
function coseToJwk(cose: Map<number, unknown>): JsonWebKey {
  const kty = cose.get(1)
  if (kty === 2) {
    // EC2,ES256 (P-256)
    return {
      kty: 'EC',
      crv: 'P-256',
      x: b64url(cose.get(-2) as Uint8Array),
      y: b64url(cose.get(-3) as Uint8Array),
    }
  }
  if (kty === 3) {
    // RSA,RS256
    return {
      kty: 'RSA',
      n: b64url(cose.get(-1) as Uint8Array),
      e: b64url(cose.get(-2) as Uint8Array),
    }
  }
  throw new Error('不支持的 COSE 密钥类型(仅支持 ES256 / RS256)')
}

// 解析 authenticatorData
function parseAuthData(ad: Uint8Array) {
  const rpIdHash = ad.slice(0, 32)
  const flags = ad[32]
  const signCount = ((ad[33] << 24) | (ad[34] << 16) | (ad[35] << 8) | ad[36]) >>> 0
  const result: { rpIdHash: Uint8Array; up: boolean; uv: boolean; at: boolean; signCount: number; credId?: Uint8Array; cose?: Map<number, unknown> } = {
    rpIdHash,
    up: !!(flags & 0x01),
    uv: !!(flags & 0x04),
    at: !!(flags & 0x40),
    signCount,
  }
  if (result.at) {
    let p = 37 + 16 // 跳过 aaguid
    const credIdLen = (ad[p] << 8) | ad[p + 1]
    p += 2
    result.credId = ad.slice(p, p + credIdLen)
    p += credIdLen
    result.cose = cborDecode(ad, p).value as Map<number, unknown>
  }
  return result
}

// ECDSA DER 签名 → raw r||s(P-256,各 32 字节)
export function derToRawEcdsa(der: Uint8Array): Uint8Array {
  let p = 0
  if (der[p++] !== 0x30) throw new Error('DER 签名格式错误')
  if (der[p] & 0x80) p += 1 + (der[p] & 0x7f); else p++ // 跳过 SEQ 长度
  const readInt = () => {
    if (der[p++] !== 0x02) throw new Error('DER INTEGER 错误')
    let len = der[p++]
    let v = der.slice(p, p + len)
    p += len
    while (v.length > 32 && v[0] === 0) v = v.slice(1)
    const out = new Uint8Array(32)
    out.set(v, 32 - v.length)
    return out
  }
  const r = readInt()
  const s = readInt()
  const raw = new Uint8Array(64)
  raw.set(r, 0)
  raw.set(s, 32)
  return raw
}

// -------------------------------------------------------------------------
// 端点
// -------------------------------------------------------------------------
function rpInfo(req: Request) {
  const url = new URL(req.url)
  return { rpId: url.hostname, origin: url.origin }
}

export async function waRegisterOptions(req: Request): Promise<Response> {
  const { rpId } = rpInfo(req)
  const body = (await req.json().catch(() => ({}))) as { username?: string }
  const username = (body.username || 'testuser').slice(0, 64)
  const challenge = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const userId = b64url(crypto.getRandomValues(new Uint8Array(16)))
  const chalJwt = await signJwt({ token_use: 'wa_reg', challenge, username, userId, exp: Math.floor(Date.now() / 1000) + 300 })
  return json(
    {
      rp: { id: rpId, name: 'Authn Mock RP' },
      user: { id: userId, name: username, displayName: username },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      timeout: 60000,
      attestation: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    },
    200,
    { 'Set-Cookie': `${CHAL_COOKIE}=${chalJwt}; HttpOnly; Secure; SameSite=Lax; Path=/webauthn; Max-Age=300` },
  )
}

export async function waRegisterVerify(req: Request): Promise<Response> {
  const { rpId, origin } = rpInfo(req)
  const cred = (await req.json().catch(() => null)) as { id?: string; response?: { clientDataJSON?: string; attestationObject?: string } } | null
  const chalRaw = readCookie(req, CHAL_COOKIE)
  if (!cred?.response || !chalRaw) return json({ ok: false, error: '缺少凭证或 challenge' }, 400)
  const ctx = await verifyJwt(chalRaw)
  if (!ctx || ctx.token_use !== 'wa_reg') return json({ ok: false, error: 'challenge 无效或过期' }, 400)

  const clientData = JSON.parse(new TextDecoder().decode(b64urlDecode(cred.response.clientDataJSON!)))
  if (clientData.type !== 'webauthn.create') return json({ ok: false, error: 'clientData.type 错误' }, 400)
  if (clientData.challenge !== ctx.challenge) return json({ ok: false, error: 'challenge 不匹配' }, 400)
  if (clientData.origin !== origin) return json({ ok: false, error: `origin 不匹配(期望 ${origin})` }, 400)

  const att = cborDecode(b64urlDecode(cred.response.attestationObject!)).value as Map<string, unknown>
  const authData = att.get('authData') as Uint8Array
  const parsed = parseAuthData(authData)
  const expectedRpHash = await sha256(new TextEncoder().encode(rpId))
  if (b64url(parsed.rpIdHash) !== b64url(expectedRpHash)) return json({ ok: false, error: 'rpIdHash 不匹配' }, 400)
  if (!parsed.up) return json({ ok: false, error: 'User Presence 未置位' }, 400)
  if (!parsed.cose || !parsed.credId) return json({ ok: false, error: '缺少 attestedCredentialData' }, 400)

  const jwk = coseToJwk(parsed.cose as Map<number, unknown>)
  const credId = b64url(parsed.credId)
  const credJwt = await signJwt({
    token_use: 'wa_cred',
    credId,
    jwk: JSON.stringify(jwk),
    username: ctx.username,
    signCount: parsed.signCount,
    exp: Math.floor(Date.now() / 1000) + 86400 * 30,
  })
  return json(
    {
      ok: true,
      message: '✔ Passkey 注册成功',
      parsed: {
        fmt: att.get('fmt'),
        credentialId: credId,
        publicKey: jwk,
        flags: { UP: parsed.up, UV: parsed.uv, AT: parsed.at },
        signCount: parsed.signCount,
      },
    },
    200,
    { 'Set-Cookie': `${CRED_COOKIE}=${credJwt}; HttpOnly; Secure; SameSite=Lax; Path=/webauthn; Max-Age=${86400 * 30}` },
  )
}

export async function waLoginOptions(req: Request): Promise<Response> {
  const credRaw = readCookie(req, CRED_COOKIE)
  const cred = credRaw ? await verifyJwt(credRaw) : null
  if (!cred || cred.token_use !== 'wa_cred') return json({ error: '尚未注册 Passkey,请先注册' }, 400)
  const challenge = b64url(crypto.getRandomValues(new Uint8Array(32)))
  const chalJwt = await signJwt({ token_use: 'wa_auth', challenge, exp: Math.floor(Date.now() / 1000) + 300 })
  return json(
    {
      challenge,
      timeout: 60000,
      rpId: rpInfo(req).rpId,
      allowCredentials: [{ type: 'public-key', id: cred.credId }],
      userVerification: 'preferred',
    },
    200,
    { 'Set-Cookie': `${CHAL_COOKIE}=${chalJwt}; HttpOnly; Secure; SameSite=Lax; Path=/webauthn; Max-Age=300` },
  )
}

export async function waLoginVerify(req: Request): Promise<Response> {
  const { rpId, origin } = rpInfo(req)
  const asrt = (await req.json().catch(() => null)) as { response?: { clientDataJSON?: string; authenticatorData?: string; signature?: string } } | null
  const chalRaw = readCookie(req, CHAL_COOKIE)
  const credRaw = readCookie(req, CRED_COOKIE)
  if (!asrt?.response || !chalRaw || !credRaw) return json({ ok: false, error: '缺少断言 / challenge / 已注册凭证' }, 400)
  const ctx = await verifyJwt(chalRaw)
  const cred = await verifyJwt(credRaw)
  if (!ctx || ctx.token_use !== 'wa_auth' || !cred || cred.token_use !== 'wa_cred') return json({ ok: false, error: 'challenge / 凭证无效' }, 400)

  const clientData = JSON.parse(new TextDecoder().decode(b64urlDecode(asrt.response.clientDataJSON!)))
  if (clientData.type !== 'webauthn.get') return json({ ok: false, error: 'clientData.type 错误' }, 400)
  if (clientData.challenge !== ctx.challenge) return json({ ok: false, error: 'challenge 不匹配' }, 400)
  if (clientData.origin !== origin) return json({ ok: false, error: `origin 不匹配(期望 ${origin})` }, 400)

  const authData = b64urlDecode(asrt.response.authenticatorData!)
  const parsed = parseAuthData(authData)
  const expectedRpHash = await sha256(new TextEncoder().encode(rpId))
  if (b64url(parsed.rpIdHash) !== b64url(expectedRpHash)) return json({ ok: false, error: 'rpIdHash 不匹配' }, 400)
  if (!parsed.up) return json({ ok: false, error: 'User Presence 未置位' }, 400)

  const jwk = JSON.parse(String(cred.jwk)) as JsonWebKey
  const ec = jwk.kty === 'EC'
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    ec ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  const clientHash = await sha256(b64urlDecode(asrt.response.clientDataJSON!))
  const signedData = new Uint8Array([...authData, ...clientHash])
  let sig = b64urlDecode(asrt.response.signature!)
  if (ec) sig = derToRawEcdsa(sig)
  const valid = await crypto.subtle.verify(
    ec ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' },
    key,
    sig,
    signedData,
  )
  if (!valid) return json({ ok: false, error: '✗ 断言签名验证失败' }, 400)
  return json({
    ok: true,
    message: '✔ Passkey 登录成功,断言签名已用注册时的公钥验证通过',
    username: cred.username,
    signCount: parsed.signCount,
    uv: parsed.uv,
  })
}

export function waHome(): Response {
  return new Response(WA_PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } })
}

const WA_PAGE = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Mock WebAuthn RP</title>
<style>
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:720px;margin:2.5rem auto;padding:0 1.2rem;color:#2c3e50;line-height:1.7}
input{padding:.5rem .6rem;border:1px solid #dcdfe6;border-radius:6px;font-size:.95rem}
.btn{padding:.6rem 1.4rem;margin:.4rem .4rem 0 0;background:#3eaf7c;color:#fff;border:none;border-radius:6px;font-size:.95rem;cursor:pointer}
pre{background:#f6f8fa;border-radius:6px;padding:.8rem;overflow-x:auto;font-size:.8rem;white-space:pre-wrap;word-break:break-all}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px;font-size:.9rem}
.ok{color:#2e7d32;font-weight:600}.bad{color:#e53935;font-weight:600}
</style></head><body>
<h1>🔑 Mock WebAuthn RP</h1>
<p>在本页(与 RP 服务端同域,rpId 匹配)完整跑通 Passkey <strong>注册</strong>与<strong>登录</strong>,服务端会真实解析 attestation、并用注册时的公钥验证登录断言的签名。</p>
<p><input id="u" value="testuser" placeholder="用户名"/></p>
<p><button class="btn" onclick="reg()">① 注册 Passkey</button>
<button class="btn" onclick="login()">② 用 Passkey 登录</button></p>
<pre id="out">准备就绪。需要支持 WebAuthn 的浏览器与认证器(平台指纹/Face ID/安全密钥)。</pre>
<p class="warn">仅供测试。凭证公钥存于你浏览器的 HttpOnly cookie(签名 JWT),不做持久化。</p>
<script>
const out=document.getElementById('out')
const show=(o,cls)=>{out.className='';if(cls)out.classList.add(cls);out.textContent=typeof o==='string'?o:JSON.stringify(o,null,2)}
const b64uToBuf=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';const b=atob(s);const a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}
const bufToB64u=b=>{const a=new Uint8Array(b);let s='';for(const x of a)s+=String.fromCharCode(x);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
async function reg(){try{
  show('① 获取注册 options…')
  const opt=await (await fetch('/webauthn/register/options',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:document.getElementById('u').value})})).json()
  opt.challenge=b64uToBuf(opt.challenge);opt.user.id=b64uToBuf(opt.user.id)
  show('② 调用 navigator.credentials.create()…请在设备上确认')
  const cred=await navigator.credentials.create({publicKey:opt})
  const payload={id:cred.id,rawId:bufToB64u(cred.rawId),type:cred.type,response:{clientDataJSON:bufToB64u(cred.response.clientDataJSON),attestationObject:bufToB64u(cred.response.attestationObject)}}
  const res=await (await fetch('/webauthn/register/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})).json()
  show(res,res.ok?'ok':'bad')
}catch(e){show('注册失败:'+e.message,'bad')}}
async function login(){try{
  show('① 获取登录 options…')
  const opt=await (await fetch('/webauthn/login/options',{method:'POST'})).json()
  if(opt.error){show(opt.error,'bad');return}
  opt.challenge=b64uToBuf(opt.challenge);opt.allowCredentials=(opt.allowCredentials||[]).map(c=>({...c,id:b64uToBuf(c.id)}))
  show('② 调用 navigator.credentials.get()…请在设备上确认')
  const asrt=await navigator.credentials.get({publicKey:opt})
  const payload={id:asrt.id,rawId:bufToB64u(asrt.rawId),type:asrt.type,response:{clientDataJSON:bufToB64u(asrt.response.clientDataJSON),authenticatorData:bufToB64u(asrt.response.authenticatorData),signature:bufToB64u(asrt.response.signature)}}
  const res=await (await fetch('/webauthn/login/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})).json()
  show(res,res.ok?'ok':'bad')
}catch(e){show('登录失败:'+e.message,'bad')}}
</script>
</body></html>`
