/**
 * Mock TOTP / HOTP 验证器(RFC 4226 / 6238)。
 * 充当"认证器 + 校验方",用于把 TOTP 作为第二因素联调、或在 CI 里取当前验证码。
 *
 * 端点:
 *   GET  /totp/            —— 说明页
 *   GET  /totp/code        —— 按 secret 计算当前验证码(方便 CI / 调试,充当 authenticator)
 *   POST /totp/verify      —— 校验一个验证码(带 ±window 时间容错)
 *
 * 仅供测试。
 */

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32Decode(s: string): Uint8Array {
  const clean = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '')
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const ch of clean) {
    const idx = B32.indexOf(ch)
    if (idx === -1) throw new Error('secret 不是合法的 Base32')
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return new Uint8Array(out)
}

const HASHES: Record<string, string> = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }

async function hotp(keyBytes: Uint8Array, counter: number, digits: number, algorithm: string): Promise<string> {
  const hash = HASHES[algorithm.toUpperCase()] || 'SHA-1'
  const buf = new ArrayBuffer(8)
  const view = new DataView(buf)
  // 64 位大端计数器(JS number 精度足够覆盖时间步长)
  view.setUint32(0, Math.floor(counter / 0x100000000))
  view.setUint32(4, counter >>> 0)
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash }, false, ['sign'])
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf))
  const offset = mac[mac.length - 1] & 0x0f
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff)
  return (bin % 10 ** digits).toString().padStart(digits, '0')
}

/** 供测试:在指定 Unix 时间(秒)计算 TOTP。 */
export async function totpAt(
  secret: string,
  unixSeconds: number,
  { period = 30, digits = 6, algorithm = 'SHA1' } = {},
): Promise<string> {
  const key = base32Decode(secret)
  return hotp(key, Math.floor(unixSeconds / period), digits, algorithm)
}

interface TotpOpts {
  period: number
  digits: number
  algorithm: string
}
function optsFrom(p: URLSearchParams): TotpOpts {
  return {
    period: Math.max(1, parseInt(p.get('period') || '30', 10)),
    digits: Math.min(10, Math.max(4, parseInt(p.get('digits') || '6', 10))),
    algorithm: p.get('algorithm') || 'SHA1',
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Access-Control-Allow-Origin': '*',
    },
  })
}

export async function totpCode(req: Request): Promise<Response> {
  const p = new URL(req.url).searchParams
  const secret = p.get('secret')
  if (!secret) return json({ error: 'missing secret（Base32）' }, 400)
  try {
    const opts = optsFrom(p)
    const key = base32Decode(secret)
    const now = Math.floor(Date.now() / 1000)
    const step = Math.floor(now / opts.period)
    const code = await hotp(key, step, opts.digits, opts.algorithm)
    return json({
      code,
      time_step: step,
      seconds_remaining: opts.period - (now % opts.period),
      period: opts.period,
      digits: opts.digits,
      algorithm: opts.algorithm.toUpperCase(),
    })
  } catch (e) {
    return json({ error: (e as Error).message }, 400)
  }
}

export async function totpVerify(req: Request): Promise<Response> {
  if (req.method !== 'POST') return json({ error: '需 POST' }, 405)
  let body: Record<string, unknown>
  try {
    const ct = req.headers.get('Content-Type') || ''
    body = ct.includes('application/json')
      ? await req.json()
      : Object.fromEntries(new URLSearchParams(await req.text()))
  } catch {
    return json({ error: '无法解析请求体' }, 400)
  }
  const secret = String(body.secret || '')
  const code = String(body.code || '').trim()
  if (!secret || !code) return json({ error: 'secret 与 code 必填' }, 400)
  const period = Math.max(1, parseInt(String(body.period || '30'), 10))
  const digits = Math.min(10, Math.max(4, parseInt(String(body.digits || '6'), 10)))
  const algorithm = String(body.algorithm || 'SHA1')
  const window = Math.min(10, Math.max(0, parseInt(String(body.window ?? '1'), 10)))
  try {
    const key = base32Decode(secret)
    const now = Math.floor(Date.now() / 1000)
    const step = Math.floor(now / period)
    for (let w = -window; w <= window; w++) {
      const expected = await hotp(key, step + w, digits, algorithm)
      if (expected === code) {
        return json({ valid: true, matched_offset: w, time_step: step + w })
      }
    }
    return json({ valid: false, checked_window: `±${window}`, time_step: step })
  } catch (e) {
    return json({ error: (e as Error).message }, 400)
  }
}

export function totpHome(issuer: string): Response {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return new Response(
    `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Mock TOTP 验证器</title>
<style>body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:720px;margin:2.5rem auto;padding:0 1.2rem;color:#2c3e50;line-height:1.7}
code,pre{font-family:ui-monospace,monospace;background:#f6f8fa;border-radius:4px}code{padding:.15rem .4rem;font-size:.88em}
pre{padding:.8rem;overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-all}
.warn{background:#fff3cd;border-left:4px solid #e0a800;padding:.7rem 1rem;border-radius:4px;font-size:.9rem}</style></head>
<body>
<h1>🔢 Mock TOTP / HOTP 验证器</h1>
<p>把 TOTP 当作第二因素来联调:本服务既能<strong>按密钥算出当前验证码</strong>(充当认证器,便于 CI),也能<strong>校验</strong>一个验证码(带 ±window 时间容错)。RFC 4226 / 6238。</p>
<h2>取当前验证码</h2>
<pre>curl "${esc(issuer)}/totp/code?secret=JBSWY3DPEHPK3PXP&period=30&digits=6&algorithm=SHA1"</pre>
<h2>校验验证码</h2>
<pre>curl -X POST ${esc(issuer)}/totp/verify \\
  -H "Content-Type: application/json" \\
  -d '{"secret":"JBSWY3DPEHPK3PXP","code":"123456","window":1}'</pre>
<p>参数:<code>secret</code>(Base32)、<code>code</code>、<code>period</code>(默认 30)、<code>digits</code>(默认 6)、<code>algorithm</code>(SHA1/SHA256/SHA512)、<code>window</code>(默认 ±1)。</p>
<p class="warn">仅供测试。生成密钥、扫码添加到验证器 App 可用文档站的
<a href="https://authn-cn.pages.dev/tools/totp">TOTP 工具</a>。</p>
</body></html>`,
    { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } },
  )
}
