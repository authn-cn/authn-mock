import { signJwt, verifyJwt, s256, type Claims } from './jwt'
import { PUBLIC_JWK } from './keys'
import { USERS, claimsForScopes, findUserBySub } from './users'
import { loginPage } from './html'

const CODE_TTL = 300
const TOKEN_TTL = 3600
const REFRESH_TTL = 86400 * 14

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS,
      ...headers,
    },
  })
}

function oauthError(error: string, description: string, status = 400): Response {
  return json({ error, error_description: description }, status)
}

function now(): number {
  return Math.floor(Date.now() / 1000)
}

// ---------------------------------------------------------------------------
// Discovery & JWKS
// ---------------------------------------------------------------------------

export function discovery(issuer: string): Response {
  return json({
    issuer,
    authorization_endpoint: `${issuer}/oidc/authorize`,
    token_endpoint: `${issuer}/oidc/token`,
    userinfo_endpoint: `${issuer}/oidc/userinfo`,
    jwks_uri: `${issuer}/oidc/jwks.json`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_basic', 'client_secret_post'],
    code_challenge_methods_supported: ['S256', 'plain'],
    claims_supported: [
      'sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce',
      'name', 'given_name', 'family_name', 'preferred_username', 'locale', 'updated_at',
      'email', 'email_verified',
    ],
  })
}

export function jwks(): Response {
  return json({ keys: [PUBLIC_JWK] })
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

export async function authorize(req: Request, issuer: string): Promise<Response> {
  const q = new URL(req.url).searchParams
  const clientId = q.get('client_id')
  const redirectUri = q.get('redirect_uri')
  const responseType = q.get('response_type')
  const scope = q.get('scope') ?? ''
  const state = q.get('state')
  const nonce = q.get('nonce')
  const codeChallenge = q.get('code_challenge')
  const codeChallengeMethod = q.get('code_challenge_method') ?? (codeChallenge ? 'plain' : null)
  const prompt = q.get('prompt')
  const user = q.get('user') // mock 专用:直接指定测试用户,跳过选择页

  // redirect_uri 无效时绝不能重定向,只能直接报错
  if (!clientId) return oauthError('invalid_request', 'client_id is required')
  if (!redirectUri || !/^https?:\/\//.test(redirectUri)) {
    return oauthError('invalid_request', 'redirect_uri is required and must be an absolute http(s) URL')
  }

  const redirectError = (error: string, description: string): Response => {
    const u = new URL(redirectUri)
    u.searchParams.set('error', error)
    u.searchParams.set('error_description', description)
    if (state) u.searchParams.set('state', state)
    return Response.redirect(u.toString(), 302)
  }

  if (responseType !== 'code') {
    return redirectError('unsupported_response_type', 'only response_type=code is supported')
  }
  const scopes = scope.split(/\s+/).filter(Boolean)
  if (!scopes.includes('openid')) {
    return redirectError('invalid_scope', 'scope must include openid')
  }
  if (codeChallenge && codeChallengeMethod !== 'S256' && codeChallengeMethod !== 'plain') {
    return redirectError('invalid_request', 'code_challenge_method must be S256 or plain')
  }

  // 未指定用户:prompt=none 直接报错,否则渲染用户选择页
  if (!user) {
    if (prompt === 'none') return redirectError('login_required', 'no session and prompt=none')
    return new Response(loginPage(q), {
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    })
  }

  const mockUser = USERS[user]
  if (!mockUser) {
    return redirectError('access_denied', `unknown mock user "${user}" (available: ${Object.keys(USERS).join(', ')})`)
  }

  // 授权码 = 短时效签名 JWT(无状态;mock 不保证单次使用)
  const code = await signJwt({
    token_use: 'code',
    iss: issuer,
    aud: clientId,
    sub: mockUser.sub,
    scope: scopes.join(' '),
    redirect_uri: redirectUri,
    nonce: nonce ?? undefined,
    code_challenge: codeChallenge ?? undefined,
    code_challenge_method: codeChallenge ? codeChallengeMethod : undefined,
    auth_time: now(),
    exp: now() + CODE_TTL,
  })

  const u = new URL(redirectUri)
  u.searchParams.set('code', code)
  if (state) u.searchParams.set('state', state)
  return Response.redirect(u.toString(), 302)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

async function issueTokens(opts: {
  issuer: string
  clientId: string
  sub: string
  scopes: string[]
  nonce?: string
  authTime?: number
}): Promise<Record<string, unknown>> {
  const { issuer, clientId, sub, scopes, nonce, authTime } = opts
  const iat = now()

  const accessToken = await signJwt({
    token_use: 'access',
    iss: issuer,
    sub,
    aud: clientId,
    client_id: clientId,
    scope: scopes.join(' '),
    iat,
    exp: iat + TOKEN_TTL,
  })

  const result: Record<string, unknown> = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: TOKEN_TTL,
    scope: scopes.join(' '),
  }

  if (scopes.includes('openid')) {
    const user = findUserBySub(sub)
    const idClaims: Claims = {
      iss: issuer,
      sub,
      aud: clientId,
      azp: clientId,
      iat,
      exp: iat + TOKEN_TTL,
      auth_time: authTime ?? iat,
    }
    if (nonce) idClaims.nonce = nonce
    if (user) Object.assign(idClaims, claimsForScopes(user, scopes), { sub })
    result.id_token = await signJwt(idClaims)
  }

  if (scopes.includes('offline_access')) {
    result.refresh_token = await signJwt({
      token_use: 'refresh',
      iss: issuer,
      sub,
      aud: clientId,
      scope: scopes.join(' '),
      nonce: nonce ?? undefined,
      exp: now() + REFRESH_TTL,
    })
  }

  return result
}

export async function token(req: Request, issuer: string): Promise<Response> {
  if (req.method !== 'POST') return oauthError('invalid_request', 'token endpoint requires POST', 405)
  const ct = req.headers.get('Content-Type') ?? ''
  if (!ct.includes('application/x-www-form-urlencoded')) {
    return oauthError('invalid_request', 'Content-Type must be application/x-www-form-urlencoded')
  }
  const form = new URLSearchParams(await req.text())
  const grantType = form.get('grant_type')

  // mock 不校验 client secret,任意 client_id 都被接受
  const clientId =
    form.get('client_id') ?? basicAuthClientId(req.headers.get('Authorization')) ?? 'mock-client'

  if (grantType === 'authorization_code') {
    const code = form.get('code')
    if (!code) return oauthError('invalid_request', 'code is required')
    const payload = await verifyJwt(code)
    if (!payload || payload.token_use !== 'code') {
      return oauthError('invalid_grant', 'code is invalid or expired')
    }
    if (payload.redirect_uri && form.get('redirect_uri') !== payload.redirect_uri) {
      return oauthError('invalid_grant', 'redirect_uri does not match the authorization request')
    }
    if (payload.code_challenge) {
      const verifier = form.get('code_verifier')
      if (!verifier) return oauthError('invalid_grant', 'code_verifier is required (PKCE was used)')
      const expected =
        payload.code_challenge_method === 'S256' ? await s256(verifier) : verifier
      if (expected !== payload.code_challenge) {
        return oauthError('invalid_grant', 'PKCE verification failed')
      }
    }
    return json(
      await issueTokens({
        issuer,
        clientId: String(payload.aud ?? clientId),
        sub: String(payload.sub),
        scopes: String(payload.scope ?? '').split(' ').filter(Boolean),
        nonce: payload.nonce ? String(payload.nonce) : undefined,
        authTime: typeof payload.auth_time === 'number' ? payload.auth_time : undefined,
      }),
    )
  }

  if (grantType === 'refresh_token') {
    const rt = form.get('refresh_token')
    if (!rt) return oauthError('invalid_request', 'refresh_token is required')
    const payload = await verifyJwt(rt)
    if (!payload || payload.token_use !== 'refresh') {
      return oauthError('invalid_grant', 'refresh_token is invalid or expired')
    }
    return json(
      await issueTokens({
        issuer,
        clientId: String(payload.aud ?? clientId),
        sub: String(payload.sub),
        scopes: String(payload.scope ?? '').split(' ').filter(Boolean),
        nonce: payload.nonce ? String(payload.nonce) : undefined,
      }),
    )
  }

  if (grantType === 'client_credentials') {
    return json(
      await issueTokens({
        issuer,
        clientId,
        sub: clientId,
        scopes: (form.get('scope') ?? 'api').split(' ').filter(Boolean),
      }),
    )
  }

  return oauthError('unsupported_grant_type', `grant_type "${grantType}" is not supported`)
}

function basicAuthClientId(header: string | null): string | null {
  if (!header?.startsWith('Basic ')) return null
  try {
    return decodeURIComponent(atob(header.slice(6)).split(':')[0])
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// UserInfo endpoint
// ---------------------------------------------------------------------------

export async function userinfo(req: Request): Promise<Response> {
  const auth = req.headers.get('Authorization')
  if (!auth?.startsWith('Bearer ')) {
    return json({ error: 'invalid_token', error_description: 'missing Bearer token' }, 401, {
      'WWW-Authenticate': 'Bearer',
    })
  }
  const payload = await verifyJwt(auth.slice(7))
  if (!payload || payload.token_use !== 'access') {
    return json({ error: 'invalid_token', error_description: 'access token is invalid or expired' }, 401, {
      'WWW-Authenticate': 'Bearer error="invalid_token"',
    })
  }
  const user = findUserBySub(String(payload.sub))
  if (!user) return json({ sub: payload.sub })
  return json(claimsForScopes(user, String(payload.scope ?? '').split(' ')))
}

export function corsPreflightResponse(): Response {
  return new Response(null, { status: 204, headers: CORS_HEADERS })
}
