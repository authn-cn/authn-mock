import { describe, expect, it } from 'vitest'
import worker from '../src/index'
import { verifyEnveloped, el, t } from '../src/xmldsig'

const ORIGIN = 'https://mock.test'

async function call(path: string, init?: RequestInit): Promise<Response> {
  return worker.fetch(new Request(ORIGIN + path, init))
}

async function deflateRaw(text: string): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw')
  const stream = new Blob([new TextEncoder().encode(text)]).stream().pipeThrough(cs)
  return new Uint8Array(await new Response(stream).arrayBuffer())
}
function bytesToB64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}
function extractAssertion(responseXml: string): string {
  const m = responseXml.match(/<saml:Assertion\b[\s\S]*?<\/saml:Assertion>/)
  if (!m) throw new Error('no assertion')
  return m[0]
}

describe('SAML IdP metadata', () => {
  it('serves signed-key metadata with SSO endpoints', async () => {
    const res = await call('/saml/idp/metadata')
    expect(res.status).toBe(200)
    const xml = await res.text()
    expect(xml).toContain('EntityDescriptor')
    expect(xml).toContain('IDPSSODescriptor')
    expect(xml).toContain('X509Certificate')
    expect(xml).toContain(`${ORIGIN}/saml/idp/sso`)
  })
})

describe('xmldsig round-trip', () => {
  it('produces a signature that verifies and whose digest matches', async () => {
    const id = '_test123'
    const assertion = el(
      'saml:Assertion',
      { 'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion', ID: id, IssueInstant: '2026-01-01T00:00:00Z', Version: '2.0' },
      el('saml:Issuer', {}, t('https://idp.example')) +
        el('saml:Subject', {}, el('saml:NameID', {}, t('alice@example.com'))),
    )
    const { signEnveloped } = await import('../src/xmldsig')
    const signed = await signEnveloped(assertion, id)
    const { signatureValid, digestValid } = await verifyEnveloped(signed)
    expect(signatureValid).toBe(true)
    expect(digestValid).toBe(true)
  })
})

describe('SP-initiated SSO', () => {
  const acs = 'https://sp.example/acs'
  const sp = 'https://sp.example/metadata'

  function authnRequest(): string {
    return el(
      'samlp:AuthnRequest',
      {
        'xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        AssertionConsumerServiceURL: acs,
        ID: '_req_abc',
        IssueInstant: '2026-01-01T00:00:00Z',
        Version: '2.0',
      },
      el('saml:Issuer', {}, t(sp)),
    )
  }

  it('renders a user-choice page for a Redirect-binding AuthnRequest', async () => {
    const b64 = bytesToB64(await deflateRaw(authnRequest()))
    const res = await call(`/saml/idp/sso?SAMLRequest=${encodeURIComponent(b64)}&RelayState=/app`)
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Alice Zhang')
    expect(html).toContain(encodeURIComponent(acs))
  })

  it('issues a signed Response with correct audience/subject/InResponseTo', async () => {
    const res = await call(
      `/saml/idp/sso?user=alice&acs=${encodeURIComponent(acs)}&sp=${encodeURIComponent(sp)}&rid=_req_abc&rs=/app`,
    )
    expect(res.status).toBe(200)
    const form = await res.text()
    // auto-post 表单里含 SAMLResponse 与 RelayState
    expect(form).toContain(`action="${acs}"`)
    expect(form).toContain('name="RelayState" value="/app"')
    const b64 = form.match(/name="SAMLResponse" value="([^"]+)"/)![1]
    const xml = new TextDecoder().decode(
      Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)),
    )
    expect(xml).toContain('urn:oasis:names:tc:SAML:2.0:status:Success')
    expect(xml).toContain('alice@mock.authn.example')
    expect(xml).toContain(`<saml:Audience>${sp}</saml:Audience>`)
    expect(xml).toContain('InResponseTo="_req_abc"')

    const assertion = extractAssertion(xml)
    const { signatureValid, digestValid } = await verifyEnveloped(assertion)
    expect(signatureValid).toBe(true)
    expect(digestValid).toBe(true)
  })

  it('supports IdP-initiated (no InResponseTo)', async () => {
    const res = await call(
      `/saml/idp/sso?user=bob&acs=${encodeURIComponent(acs)}&sp=${encodeURIComponent(sp)}`,
    )
    const form = await res.text()
    const b64 = form.match(/name="SAMLResponse" value="([^"]+)"/)![1]
    const xml = new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)))
    expect(xml).toContain('bob@mock.authn.example')
    expect(xml).not.toContain('InResponseTo')
    const { signatureValid } = await verifyEnveloped(extractAssertion(xml))
    expect(signatureValid).toBe(true)
  })
})

describe('OIDC RP console', () => {
  it('renders the RP config form', async () => {
    const res = await call('/rp/')
    expect(res.status).toBe(200)
    const html = await res.text()
    expect(html).toContain('Mock OIDC RP')
    expect(html).toContain('/rp/start')
    expect(html).toContain(`${ORIGIN}/rp/callback`)
  })
})
