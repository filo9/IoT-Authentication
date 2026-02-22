// ==========================================
// 后量子密码学模块 (浏览器端)
// ML-KEM-768 模拟 + Web Crypto API
// ==========================================
import type { PQCKeyPair, KEMEncapsResult, ECDHKeyPair } from './types'

const MLKEM768_PK_SIZE = 1184
const MLKEM768_SK_SIZE = 2400
const MLKEM768_CT_SIZE = 1088
const MLKEM768_SS_SIZE = 32

// ==========================================
// 工具函数
// ==========================================
function randomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len)
  crypto.getRandomValues(buf)
  return buf
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

function strToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

// ==========================================
// SHA-256 哈希
// ==========================================
export async function hash(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(digest)
}

// ==========================================
// HMAC-SHA256 (PRF)
// ==========================================
export async function hmacSHA256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data)
  return new Uint8Array(sig)
}

// ==========================================
// HKDF
// ==========================================
export async function hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
  const effectiveSalt = salt.length === 0 ? new Uint8Array(32) : salt
  return hmacSHA256(effectiveSalt, ikm)
}

export async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
  const okm = new Uint8Array(length)
  let tPrev = new Uint8Array(0)
  let offset = 0
  let counter = 1
  while (offset < length) {
    const input = concatBytes(tPrev, info, new Uint8Array([counter++]))
    tPrev = await hmacSHA256(prk, input)
    const copyLen = Math.min(tPrev.length, length - offset)
    okm.set(tPrev.subarray(0, copyLen), offset)
    offset += copyLen
  }
  return okm
}

// ==========================================
// ML-KEM-768 模拟 (与 C++ CryptoModulePQC 完全对称)
// ==========================================
export async function kemKeyGen(): Promise<PQCKeyPair> {
  const seedD = randomBytes(32)
  const seedZ = randomBytes(32)

  const prkPk = await hkdfExtract(new Uint8Array(0), seedD)
  const pk = await hkdfExpand(prkPk, strToBytes('mlkem768-pk-derivation'), MLKEM768_PK_SIZE)

  // sk = seedD(32) || seedZ(32) || pk(1184) || padding
  let sk = concatBytes(seedD, seedZ, pk)
  if (sk.length < MLKEM768_SK_SIZE) {
    const padding = await hkdfExpand(prkPk, strToBytes('skpad'), MLKEM768_SK_SIZE - sk.length)
    sk = concatBytes(sk, padding)
  }
  return { publicKey: pk, secretKey: sk.subarray(0, MLKEM768_SK_SIZE) }
}

export async function kemEncaps(publicKey: Uint8Array): Promise<KEMEncapsResult> {
  if (publicKey.length !== MLKEM768_PK_SIZE) throw new Error('Invalid ML-KEM public key size')

  const coin = randomBytes(32)
  const ikm = concatBytes(publicKey, coin)
  const prk = await hkdfExtract(new Uint8Array(0), ikm)

  const sharedSecret = await hkdfExpand(prk, strToBytes('mlkem768-shared-secret'), MLKEM768_SS_SIZE)
  const ct = await hkdfExpand(prk, strToBytes('mlkem768-ciphertext'), MLKEM768_CT_SIZE)

  // 嵌入 coin tag
  const pkHash = await hash(publicKey)
  const coinTag = await hmacSHA256(pkHash, coin)
  ct.set(coinTag.subarray(0, 32), MLKEM768_CT_SIZE - 32)

  // 加密 coin
  const coinMask = await hkdfExpand(await hkdfExtract(new Uint8Array(0), publicKey), strToBytes('mlkem768-coin-mask'), 32)
  for (let i = 0; i < 32; i++) ct[i] = coin[i] ^ coinMask[i]

  return { ciphertext: ct, sharedSecret }
}

export async function kemDecaps(secretKey: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (secretKey.length !== MLKEM768_SK_SIZE) throw new Error('Invalid ML-KEM secret key size')
  if (ciphertext.length !== MLKEM768_CT_SIZE) throw new Error('Invalid ML-KEM ciphertext size')

  const seedZ = secretKey.subarray(32, 64)
  const pk = secretKey.subarray(64, 64 + MLKEM768_PK_SIZE)

  // 恢复 coin
  const coinMask = await hkdfExpand(await hkdfExtract(new Uint8Array(0), pk), strToBytes('mlkem768-coin-mask'), 32)
  const coin = new Uint8Array(32)
  for (let i = 0; i < 32; i++) coin[i] = ciphertext[i] ^ coinMask[i]

  // 验证 tag
  const pkHash = await hash(pk)
  const expectedTag = await hmacSHA256(pkHash, coin)
  let tagValid = true
  for (let i = 0; i < 32; i++) {
    if (ciphertext[MLKEM768_CT_SIZE - 32 + i] !== expectedTag[i]) { tagValid = false; break }
  }

  if (!tagValid) {
    // 隐式拒绝
    const rejectInput = concatBytes(seedZ, ciphertext)
    const reject = await hash(rejectInput)
    return reject.subarray(0, MLKEM768_SS_SIZE)
  }

  const ikm = concatBytes(pk, coin)
  const prk = await hkdfExtract(new Uint8Array(0), ikm)
  return hkdfExpand(prk, strToBytes('mlkem768-shared-secret'), MLKEM768_SS_SIZE)
}

// ==========================================
// ECDH P-256 (Web Crypto API — 用于性能对比)
// ==========================================
export async function ecdhKeyGen(): Promise<ECDHKeyPair> {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const pubRaw = await crypto.subtle.exportKey('raw', kp.publicKey)
  return {
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    publicKeyRaw: new Uint8Array(pubRaw)
  }
}

export async function ecdhDeriveBits(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Uint8Array> {
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256)
  return new Uint8Array(bits)
}

// ==========================================
// ECDSA 签名/验签 (Web Crypto API)
// ==========================================
export async function ecdsaKeyGen(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
}

export async function ecdsaSign(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data)
  return new Uint8Array(sig)
}

export async function ecdsaVerify(publicKey: CryptoKey, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, data)
}

// 导出常量
export const KEM_PARAMS = {
  PK_SIZE: MLKEM768_PK_SIZE,
  SK_SIZE: MLKEM768_SK_SIZE,
  CT_SIZE: MLKEM768_CT_SIZE,
  SS_SIZE: MLKEM768_SS_SIZE
}
