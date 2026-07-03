/**
 * SAML 用的 XML 数字签名(enveloped signature + 排他规范化 exc-c14n)。
 *
 * Cloudflare Workers 运行时没有 DOMParser/XMLSerializer,无法做通用 C14N。
 * 这里采用"生成即规范化"策略:所有 XML 都通过 el()/t() 构造成已经是
 * exclusive canonical 形式的字符串,于是可以直接对字符串算 digest / 签名,
 * 无需运行时规范化。调用方必须只用本模块的 helper 构造被签名的元素。
 *
 * 规范化要点(已在 el()/t() 中实现):
 *  - 属性排序:命名空间声明在前(default 最前,其余按前缀),普通属性按 localName;
 *  - 空元素写成 <x></x> 而非 <x/>;
 *  - 属性值转义 & < " \t \n \r;文本转义 & < > \r;
 *  - 元素之间不插入任何空白。
 */
import { b64urlDecode } from './jwt'
import { PRIVATE_JWK, SAML_CERT_B64 } from './keys'

const DS = 'http://www.w3.org/2000/09/xmldsig#'
const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256'
const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'

export function escapeText(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r/g, '&#xD;')
}

export function escapeAttr(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;')
    .replace(/\r/g, '&#xD;')
}

/** 转义后的文本节点。 */
export function t(s: string): string {
  return escapeText(s)
}

type Attrs = Record<string, string | undefined>

/**
 * 构造一个规范化的元素字符串。
 * attrs 中 key 以 "xmlns" 或 "xmlns:" 开头的视为命名空间声明,排在最前;
 * 其余普通属性按冒号后的 localName 字母序排列。值为 undefined 的属性被忽略。
 * inner 应是已构造好的子元素/已转义文本(用 t())。
 */
export function el(tag: string, attrs: Attrs, inner = ''): string {
  const entries = Object.entries(attrs).filter(([, v]) => v !== undefined) as [string, string][]
  const ns = entries
    .filter(([k]) => k === 'xmlns' || k.startsWith('xmlns:'))
    .sort(([a], [b]) => (a === 'xmlns' ? '' : a).localeCompare(b === 'xmlns' ? '' : b))
  const normal = entries
    .filter(([k]) => k !== 'xmlns' && !k.startsWith('xmlns:'))
    .sort(([a], [b]) => localName(a).localeCompare(localName(b)))
  const attrStr = [...ns, ...normal]
    .map(([k, v]) => ` ${k}="${escapeAttr(v)}"`)
    .join('')
  return `<${tag}${attrStr}>${inner}</${tag}>`
}

function localName(qname: string): string {
  const i = qname.indexOf(':')
  return i === -1 ? qname : qname.slice(i + 1)
}

// --------------------------------------------------------------------------
// 加密原语
// --------------------------------------------------------------------------

const RSA = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const
let signKeyPromise: Promise<CryptoKey> | null = null

function signingKey(): Promise<CryptoKey> {
  signKeyPromise ??= crypto.subtle.importKey('jwk', PRIVATE_JWK, RSA, false, ['sign'])
  return signKeyPromise
}

function bytesToB64(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

async function sha256B64(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return bytesToB64(new Uint8Array(digest))
}

/** 证书 base64 DER 换行成 PEM body(每 64 字符),SAML KeyInfo 里通常直接用单行也可。 */
export function certPem(): string {
  return SAML_CERT_B64
}

// --------------------------------------------------------------------------
// enveloped 签名
// --------------------------------------------------------------------------

/**
 * 对一个"已规范化、且尚未含 Signature"的元素做 enveloped 签名,
 * 返回 <ds:Signature> 字符串。调用方负责把它插入到被签元素内部(SAML 规定
 * 紧跟 Issuer 之后)。
 *
 * @param canonicalSubtree 被签元素的完整规范化 XML(不含 Signature),
 *        其 exc-c14n 形式必须等于自身(用 el() 构造即满足)。
 * @param refId 被签元素的 ID 属性值(Reference URI 会指向 #refId)。
 */
export async function buildSignature(canonicalSubtree: string, refId: string): Promise<string> {
  const digestValue = await sha256B64(canonicalSubtree)

  // SignedInfo 必须自带 xmlns:ds:验证方会把它单独 exc-c14n,
  // 结果就是带一个 xmlns:ds 的 SignedInfo,与此处一致。
  const signedInfo = el(
    'ds:SignedInfo',
    { 'xmlns:ds': DS },
    el('ds:CanonicalizationMethod', { Algorithm: EXC_C14N }) +
      el('ds:SignatureMethod', { Algorithm: RSA_SHA256 }) +
      el(
        'ds:Reference',
        { URI: `#${refId}` },
        el(
          'ds:Transforms',
          {},
          el('ds:Transform', { Algorithm: ENVELOPED }) +
            el('ds:Transform', { Algorithm: EXC_C14N }),
        ) +
          el('ds:DigestMethod', { Algorithm: SHA256 }) +
          el('ds:DigestValue', {}, digestValue),
      ),
  )

  const sigBytes = await crypto.subtle.sign(RSA, await signingKey(), new TextEncoder().encode(signedInfo))
  const signatureValue = bytesToB64(new Uint8Array(sigBytes))

  return el(
    'ds:Signature',
    { 'xmlns:ds': DS },
    signedInfo +
      el('ds:SignatureValue', {}, signatureValue) +
      el(
        'ds:KeyInfo',
        {},
        el('ds:X509Data', {}, el('ds:X509Certificate', {}, SAML_CERT_B64)),
      ),
  )
}

/**
 * 便捷函数:被签元素以 </saml:Issuer> 结尾处插入 Signature(SAML Assertion/Response
 * 都要求 Signature 紧跟 Issuer)。传入的 subtree 必须是规范化字符串。
 */
export async function signEnveloped(canonicalSubtree: string, refId: string): Promise<string> {
  const signature = await buildSignature(canonicalSubtree, refId)
  const marker = '</saml:Issuer>'
  const idx = canonicalSubtree.indexOf(marker)
  if (idx === -1) throw new Error('signEnveloped: no <saml:Issuer> found to anchor signature')
  const at = idx + marker.length
  return canonicalSubtree.slice(0, at) + signature + canonicalSubtree.slice(at)
}

// --------------------------------------------------------------------------
// 供测试:用公钥验证 SignedInfo 签名 + 校验 digest(round-trip)
// --------------------------------------------------------------------------

let verifyKeyPromise: Promise<CryptoKey> | null = null
function verifyKey(): Promise<CryptoKey> {
  const { d, p, q, dp, dq, qi, ...pub } = PRIVATE_JWK as unknown as Record<string, unknown>
  verifyKeyPromise ??= crypto.subtle.importKey('jwk', pub as unknown as JsonWebKey, RSA, false, ['verify'])
  return verifyKeyPromise
}

/** 从签名后的元素中抽出 SignedInfo,验签,并重算被签子树 digest 做对比。 */
export async function verifyEnveloped(signedElement: string): Promise<{
  signatureValid: boolean
  digestValid: boolean
}> {
  const signedInfo = extractBetween(signedElement, '<ds:SignedInfo ', '</ds:SignedInfo>')
  const sigValueB64 = extractBetween(signedElement, '<ds:SignatureValue>', '</ds:SignatureValue>')
    ?.replace(/[\r\n\s]/g, '')
  const digestValue = extractBetween(signedElement, '<ds:DigestValue>', '</ds:DigestValue>')
  if (!signedInfo || !sigValueB64 || !digestValue) {
    return { signatureValid: false, digestValid: false }
  }
  const signatureValid = await crypto.subtle.verify(
    RSA,
    await verifyKey(),
    b64ToBytes(sigValueB64),
    new TextEncoder().encode('<ds:SignedInfo ' + signedInfo + '</ds:SignedInfo>'),
  )
  // enveloped transform:移除整个 <ds:Signature>...</ds:Signature>
  const withoutSig = signedElement.replace(/<ds:Signature\b[\s\S]*?<\/ds:Signature>/, '')
  const digestValid = (await sha256B64(withoutSig)) === digestValue
  return { signatureValid, digestValid }
}

function extractBetween(s: string, start: string, end: string): string | null {
  const i = s.indexOf(start)
  if (i === -1) return null
  const j = s.indexOf(end, i + start.length)
  if (j === -1) return null
  return s.slice(i + start.length, j)
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

// 供 saml.ts 复用:URL-safe base64 解码(Redirect Binding 的 SAMLRequest)
export { b64urlDecode }
