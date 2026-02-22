// ==========================================
// 后量子协议 — 模拟服务器 (浏览器内)
// ==========================================
import type { ProtocolStep } from './types'
import {
  kemKeyGen, kemDecaps, hash, hmacSHA256,
  hkdfExtract, hkdfExpand, ecdsaKeyGen, ecdsaSign, ecdsaVerify,
  bytesToHex, KEM_PARAMS
} from './pqc-crypto'

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const arr of arrays) { result.set(arr, offset); offset += arr.length }
  return result
}
function strToBytes(s: string): Uint8Array { return new TextEncoder().encode(s) }

export class PQCServer {
  private sigKeyPair: CryptoKeyPair | null = null
  private kemKeyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null
  private serversigm: Uint8Array | null = null
  private registeredUsers: Map<string, { pkSig: CryptoKey }> = new Map()
  private sessionKeys: Map<string, Uint8Array> = new Map()
  public logs: ProtocolStep[] = []
  public perfMetrics = { kemKeyGenTime: 0, kemDecapsTime: 0, signTime: 0, verifyTime: 0, hkdfTime: 0, totalAuthTime: 0 }

  async init() {
    this.sigKeyPair = await ecdsaKeyGen()
  }

  getPublicSignKey(): CryptoKey { return this.sigKeyPair!.publicKey }

  async register(uid: string, pkSig: CryptoKey) {
    this.registeredUsers.set(uid, { pkSig })
    this.logs.push({
      step: 0, title: '注册完成', description: `用户 ${uid} 已注册到服务器数据库`,
      sender: 'server', data: { uid }, timeMs: 0,
      timestamp: new Date().toLocaleTimeString()
    })
  }

  // 步骤 2: 生成 ML-KEM 挑战
  async generateChallenge(uid: string): Promise<{
    pkKEM: Uint8Array; serversigm: Uint8Array; timestamp: number; nonce: Uint8Array
  }> {
    const t0 = performance.now()

    if (!this.registeredUsers.has(uid)) throw new Error('User not registered')

    // ML-KEM KeyGen
    const tKem0 = performance.now()
    this.kemKeyPair = await kemKeyGen()
    this.perfMetrics.kemKeyGenTime = (performance.now() - tKem0) * 1000

    const timestamp = Date.now()
    const nonce = crypto.getRandomValues(new Uint8Array(16))

    // 签名 pk_KEM
    const tSign0 = performance.now()
    this.serversigm = await ecdsaSign(this.sigKeyPair!.privateKey, this.kemKeyPair.publicKey)
    this.perfMetrics.signTime = (performance.now() - tSign0) * 1000

    this.logs.push({
      step: 2, title: '服务器生成挑战 (ML-KEM)',
      description: `生成 ML-KEM-768 临时密钥对\npk_KEM: ${KEM_PARAMS.PK_SIZE} bytes\n签名 pk_KEM`,
      sender: 'server',
      data: {
        'pk_KEM (前32字节)': bytesToHex(this.kemKeyPair.publicKey.subarray(0, 32)) + '...',
        'KEM KeyGen': this.perfMetrics.kemKeyGenTime.toFixed(0) + ' μs',
        'Sign': this.perfMetrics.signTime.toFixed(0) + ' μs'
      },
      timeMs: performance.now() - t0,
      timestamp: new Date().toLocaleTimeString()
    })

    return { pkKEM: this.kemKeyPair.publicKey, serversigm: this.serversigm, timestamp, nonce }
  }

  // 步骤 4: 验证客户端响应 + KEM Decaps
  async processResponse(uid: string, tau: { sigma: Uint8Array; ct: Uint8Array }, tagU: Uint8Array): Promise<{
    success: boolean; tagS: Uint8Array; serversigtag: Uint8Array
  }> {
    const t0 = performance.now()
    const user = this.registeredUsers.get(uid)
    if (!user || !this.kemKeyPair) throw new Error('Invalid session')

    // 验证用户签名
    const sigData = concatBytes(strToBytes(uid), this.kemKeyPair.publicKey, tau.ct, tagU)
    const tVerify0 = performance.now()
    const valid = await ecdsaVerify(user.pkSig, sigData, tau.sigma)
    this.perfMetrics.verifyTime = (performance.now() - tVerify0) * 1000
    if (!valid) throw new Error('User signature verification failed')

    // ML-KEM Decaps
    const tDecaps0 = performance.now()
    const sharedSecret = await kemDecaps(this.kemKeyPair.secretKey, tau.ct)
    this.perfMetrics.kemDecapsTime = (performance.now() - tDecaps0) * 1000

    // 验证 tagU
    const expectedTagU = await hash(concatBytes(
      sharedSecret, strToBytes(uid), this.kemKeyPair.publicKey,
      this.serversigm!, tau.ct, strToBytes('clientconfirm')
    ))
    if (bytesToHex(expectedTagU) !== bytesToHex(tagU)) throw new Error('tagU mismatch')

    // HKDF 密钥派生
    const tHkdf0 = performance.now()
    const hkdfSalt = concatBytes(this.kemKeyPair.publicKey, tau.ct)
    const prk = await hkdfExtract(hkdfSalt, sharedSecret)
    const sessionKey = await hkdfExpand(prk, strToBytes('sessionkey'), 32)
    this.perfMetrics.hkdfTime = (performance.now() - tHkdf0) * 1000

    this.sessionKeys.set(uid, sessionKey)

    // 生成 tagS
    const tagS = await hash(concatBytes(
      sharedSecret, strToBytes(uid), tau.sigma, // 简化: 用 sigma 代替完整 tau
      this.kemKeyPair.publicKey, tagU, strToBytes('serverconfirm')
    ))
    const serversigtag = await ecdsaSign(this.sigKeyPair!.privateKey, tagS)

    this.perfMetrics.totalAuthTime = performance.now() - t0

    this.logs.push({
      step: 4, title: '服务器验证完成 (KEM Decaps)',
      description: `ML-KEM 解封装成功\n用户签名验证通过\nHKDF 双向密钥派生完成`,
      sender: 'server',
      data: {
        'KEM Decaps': this.perfMetrics.kemDecapsTime.toFixed(0) + ' μs',
        'Verify': this.perfMetrics.verifyTime.toFixed(0) + ' μs',
        'HKDF': this.perfMetrics.hkdfTime.toFixed(0) + ' μs',
        'Session Key': bytesToHex(sessionKey).substring(0, 32) + '...'
      },
      timeMs: performance.now() - t0,
      timestamp: new Date().toLocaleTimeString()
    })

    return { success: true, tagS, serversigtag }
  }

  getSessionKey(uid: string): Uint8Array | undefined { return this.sessionKeys.get(uid) }
}
