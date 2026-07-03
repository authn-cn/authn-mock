export interface MockUser {
  sub: string
  profile: Record<string, unknown>
  email: Record<string, unknown>
}

/** 固定测试用户,claims 按 OIDC 标准 scope 分组 */
export const USERS: Record<string, MockUser> = {
  alice: {
    sub: 'mock-user-alice',
    profile: {
      name: 'Alice Zhang',
      given_name: 'Alice',
      family_name: 'Zhang',
      preferred_username: 'alice',
      locale: 'zh-CN',
      updated_at: 1735689600,
    },
    email: {
      email: 'alice@mock.authn.example',
      email_verified: true,
    },
  },
  bob: {
    sub: 'mock-user-bob',
    profile: {
      name: 'Bob Li',
      given_name: 'Bob',
      family_name: 'Li',
      preferred_username: 'bob',
      locale: 'en-US',
      updated_at: 1735689600,
    },
    email: {
      email: 'bob@mock.authn.example',
      email_verified: false,
    },
  },
}

export function findUserBySub(sub: string): MockUser | undefined {
  return Object.values(USERS).find((u) => u.sub === sub)
}

/** 按请求的 scope 返回该用户应披露的 claims */
export function claimsForScopes(user: MockUser, scopes: string[]): Record<string, unknown> {
  const claims: Record<string, unknown> = { sub: user.sub }
  if (scopes.includes('profile')) Object.assign(claims, user.profile)
  if (scopes.includes('email')) Object.assign(claims, user.email)
  return claims
}
