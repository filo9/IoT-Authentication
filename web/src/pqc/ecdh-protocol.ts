// ==========================================
// ECDH 协议 — 模拟服务器 (浏览器内，用于对比)
// ==========================================
import {
  hash, hkdfExtract, hkdfExpand,
  ecdhKeyGen, ecdhDeriveBits,
  ecdsaKeyGen, ecdsaSign, ecdsaVerify,
  bytesToHex
} from './pqc-crypto'
import type { ECDHKeyPair } from './types'

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const arr of arrays) { result.set(arr, offset); offset += arr.length }
  return result
}
function strToBytes(s: string): Uint8Array { return new TextEncoder().encode(s) }

export class ECDHServer {
  private sigKeyPair: CryptoKeyPair | null = null
  private dhKeyPair: ECDHKeyPair | null = null
  private serversigm: Uint8Array | null = null
  private registeredUsers: Map<string, { pkSig: CryptoKey }> = new Map()
  private sessionKeys: Map<string, Uint8Array> = new Map()
  public perfMetrics = { dhKeyGenTime: 0, ecdhComputeTime: 0, signTime: 0, verifyTime: 0, hkdfTime: 0, totalAuthTime: 0 }

  async init() { this.sigKeyPair = await ecdsaKeyGen() }
  getPublicSignKey(): CryptoKey { return this.sigKeyPair!.publicKey }

  async register(uid: string, pkSig: CryptoKey) {
    this.registeredUsers.set(uid, { pkSig })
  }

  // 步骤 2: 生成 ECDH 挑战
  async generateChallenge(uid: string): Promise<{
    dhPubS: Uint8Array; serversigm: Uint8Array; timestamp: number; nonce: Uint8Array
    dhPublicKey: CryptoKey
  }> {
    if (!this.registeredUsers.has(uid)) throw new Error('User not registered')

    const t0 = performance.now()
    this.dhKeyPair = await ecdhKeyGen()
    this.perfMetrics.dhKeyGenTime = (performance.now() - t0) * 1000

    const timestamp = Date.now()
    const nonce = crypto.getRandomValues(new Uint8Array(16))

    const tSign = performance.now()
    this.serversigm = await ecdsaSign(this.sigKeyPair!.privateKey, this.dhKeyPair.publicKeyRaw)
    this.perfMetrics.signTime = (performance.now() - tSign) * 1000

    return {
      dhPubS: this.dhKeyPair.publicKeyRaw,
      serversigm: this.serversigm,
      timestamp, nonce,
      dhPublicKey: this.dhKeyPair.publicKey
    }
  }

  // 步骤 4: 验证 + ECDH 共享秘密
  async processResponse(uid: string, data: {
    sigma: Uint8Array; dhPubURaw: Uint8Array; dhPubU: CryptoKey; tagU: Uint8Array
  }): Promise<{ success: boolean; tagS: Uint8Array; serversigtag: Uint8Array }> {
    const t0 = performance.now()
    const user = this.registeredUsers.get(uid)
    if (!user || !this.dhKeyPair) throw new Error('Invalid session')

    // 验证签名
    const sigData = concatBytes(strToBytes(uid), this.dhKeyPair.publicKeyRaw, data.dhPubURaw, data.tagU)
    const tV = performance.now()
    const valid = await ecdsaVerify(user.pkSig, sigData, data.sigma)
    this.perfMetrics.verifyTime = (performance.now() - tV) * 1000
    if (!valid) throw new Error('User signature verification failed')

    // ECDH 共享秘密
    const tDH = performance.now()
    const sharedSecret = await ecdhDeriveBits(this.dhKeyPair.privateKey, data.dhPubU)
    this.perfMetrics.ecdhComputeTime = (performance.now() - tDH) * 1000

    // 验证 tagU
    const expectedTagU = await hash(concatBytes(
      sharedSecret, strToBytes(uid), this.dhKeyPair.publicKeyRaw,
      this.serversigm!, data.dhPubURaw, strToBytes('clientconfirm')
    ))
    if (bytesToHex(expectedTagU) !== bytesToHex(data.tagU)) throw new Error('tagU mismatch')

    // HKDF
    const tH = performance.now()
    const hkdfSalt = concatBytes(this.dhKeyPair.publicKeyRaw, data.dhPubURaw)
    const prk = await hkdfExtract(hkdfSalt, sharedSecret)
    const sessionKey = await hkdfExpand(prk, strToBytes('sessionkey'), 32)
    this.perfMetrics.hkdfTime = (performance.now() - tH) * 1000
    this.sessionKeys.set(uid, sessionKey)

    // tagS
    const tagS = await hash(concatBytes(
      sharedSecret, strToBytes(uid), data.sigma,
      this.dhKeyPair.publicKeyRaw, data.tagU, strToBytes('serverconfirm')
    ))
    const serversigtag = await ecdsaSign(this.sigKeyPair!.privateKey, tagS)
    this.perfMetrics.totalAuthTime = performance.now() - t0
    return { success: true, tagS, serversigtag }
  }

  getSessionKey(uid: string): Uint8Array | undefined { return this.sessionKeys.get(uid) }
}

export class ECDHClient {
  private uid: string
  private sigKeyPair: CryptoKeyPair | null = null
  private serverPubKey: CryptoKey | null = null
  private dhKeyPair: ECDHKeyPair | null = null
  private sharedSecret: Uint8Array | null = null
  private peerDHPubRaw: Uint8Array | null = null
  private serverSigM: Uint8Array | null = null
  private sigma: Uint8Array | null = null
  private tagU: Uint8Array | null = null
  private sessionKey: Uint8Array | null = null
  public perfMetrics = { dhKeyGenTime: 0, ecdhComputeTime: 0, signTime: 0, verifyTime: 0, hkdfTime: 0, totalAuthTime: 0 }

  constructor(uid: string) { this.uid = uid }

  async register(serverPubKey: CryptoKey): Promise<{ uid: string; pkSig: CryptoKey }> {
    this.sigKeyPair = await ecdsaKeyGen()
    this.serverPubKey = serverPubKey
    return { uid: this.uid, pkSig: this.sigKeyPair.publicKey }
  }

  // 步骤 3: ECDH
  async processChallenge(challenge: {
    dhPubS: Uint8Array; serversigm: Uint8Array; timestamp: number; nonce: Uint8Array
    dhPublicKey: CryptoKey
  }): Promise<{ sigma: Uint8Array; dhPubURaw: Uint8Array; dhPubU: CryptoKey; tagU: Uint8Array }> {
    // 验证时间戳
    if (Date.now() - challenge.timestamp > 30000) throw new Error('Challenge expired')

    // 验证服务器签名
    const tV = performance.now()
    const valid = await ecdsaVerify(this.serverPubKey!, challenge.dhPubS, challenge.serversigm)
    this.perfMetrics.verifyTime = (performance.now() - tV) * 1000
    if (!valid) throw new Error('Server signature invalid')

    this.peerDHPubRaw = challenge.dhPubS
    this.serverSigM = challenge.serversigm

    // ECDH KeyGen
    const tDH = performance.now()
    this.dhKeyPair = await ecdhKeyGen()
    this.perfMetrics.dhKeyGenTime = (performance.now() - tDH) * 1000

    // ECDH 共享秘密
    const tSS = performance.now()
    this.sharedSecret = await ecdhDeriveBits(this.dhKeyPair.privateKey, challenge.dhPublicKey)
    this.perfMetrics.ecdhComputeTime = (performance.now() - tSS) * 1000

    // tagU
    this.tagU = await hash(concatBytes(
      this.sharedSecret, strToBytes(this.uid), challenge.dhPubS,
      challenge.serversigm, this.dhKeyPair.publicKeyRaw, strToBytes('clientconfirm')
    ))

    // sigma
    const sigData = concatBytes(strToBytes(this.uid), challenge.dhPubS, this.dhKeyPair.publicKeyRaw, this.tagU)
    const tS = performance.now()
    this.sigma = await ecdsaSign(this.sigKeyPair!.privateKey, sigData)
    this.perfMetrics.signTime = (performance.now() - tS) * 1000

    return { sigma: this.sigma, dhPubURaw: this.dhKeyPair.publicKeyRaw, dhPubU: this.dhKeyPair.publicKey, tagU: this.tagU }
  }

  // 步骤 5
  async finalize(confirmation: { success: boolean; tagS: Uint8Array; serversigtag: Uint8Array }): Promise<boolean> {
    if (!confirmation.success) return false
    const valid = await ecdsaVerify(this.serverPubKey!, confirmation.tagS, confirmation.serversigtag)
    if (!valid) throw new Error('Server confirmation signature invalid')

    const expectedTagS = await hash(concatBytes(
      this.sharedSecret!, strToBytes(this.uid), this.sigma!,
      this.peerDHPubRaw!, this.tagU!, strToBytes('serverconfirm')
    ))
    if (bytesToHex(expectedTagS) !== bytesToHex(confirmation.tagS)) throw new Error('tagS mismatch')

    const tH = performance.now()
    const hkdfSalt = concatBytes(this.peerDHPubRaw!, this.dhKeyPair!.publicKeyRaw)
    const prk = await hkdfExtract(hkdfSalt, this.sharedSecret!)
    this.sessionKey = await hkdfExpand(prk, strToBytes('sessionkey'), 32)
    this.perfMetrics.hkdfTime = (performance.now() - tH) * 1000
    this.perfMetrics.totalAuthTime = this.perfMetrics.verifyTime + this.perfMetrics.dhKeyGenTime +
      this.perfMetrics.ecdhComputeTime + this.perfMetrics.signTime + this.perfMetrics.hkdfTime
    return true
  }

  getSessionKey(): Uint8Array | null { return this.sessionKey }
}
