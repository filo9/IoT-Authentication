// ==========================================
// 后量子协议 — 模拟客户端 (浏览器内)
// ==========================================
import type { ProtocolStep } from './types'
import {
  kemEncaps, hash, hkdfExtract, hkdfExpand,
  ecdsaKeyGen, ecdsaSign, ecdsaVerify,
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

export class PQCClient {
  private uid: string
  private sigKeyPair: CryptoKeyPair | null = null
  private serverPubKey: CryptoKey | null = null

  // 认证临时状态
  private kemCiphertext: Uint8Array | null = null
  private sharedSecret: Uint8Array | null = null
  private peerKEMPub: Uint8Array | null = null
  private serverSigM: Uint8Array | null = null
  private tau: { sigma: Uint8Array; ct: Uint8Array } | null = null
  private tagU: Uint8Array | null = null

  public logs: ProtocolStep[] = []
  public perfMetrics = { kemEncapsTime: 0, signTime: 0, verifyTime: 0, hkdfTime: 0, totalAuthTime: 0 }
  private sessionKey: Uint8Array | null = null

  constructor(uid: string) { this.uid = uid }

  // 注册
  async register(serverPubKey: CryptoKey): Promise<{ uid: string; pkSig: CryptoKey }> {
    this.sigKeyPair = await ecdsaKeyGen()
    this.serverPubKey = serverPubKey

    this.logs.push({
      step: 0, title: '客户端注册',
      description: `生成 ECDSA 签名密钥对\n保存服务器公钥`,
      sender: 'client', data: { uid: this.uid }, timeMs: 0,
      timestamp: new Date().toLocaleTimeString()
    })

    return { uid: this.uid, pkSig: this.sigKeyPair.publicKey }
  }

  // 步骤 1: 发起认证
  initiateAuth(): string {
    this.logs.push({
      step: 1, title: '发起认证请求',
      description: `发送 UID: ${this.uid}`,
      sender: 'client', data: { uid: this.uid }, timeMs: 0,
      timestamp: new Date().toLocaleTimeString()
    })
    return this.uid
  }

  // 步骤 3: 处理挑战 + KEM Encaps
  async processChallenge(challenge: {
    pkKEM: Uint8Array; serversigm: Uint8Array; timestamp: number; nonce: Uint8Array
  }): Promise<{ tau: { sigma: Uint8Array; ct: Uint8Array }; tagU: Uint8Array }> {
    const t0 = performance.now()

    // 验证时间戳
    const now = Date.now()
    if (now - challenge.timestamp > 30000) throw new Error('Challenge expired')

    // 验证服务器签名
    const tVerify0 = performance.now()
    const sigValid = await ecdsaVerify(this.serverPubKey!, challenge.pkKEM, challenge.serversigm)
    this.perfMetrics.verifyTime = (performance.now() - tVerify0) * 1000
    if (!sigValid) throw new Error('Server signature invalid')

    this.peerKEMPub = challenge.pkKEM
    this.serverSigM = challenge.serversigm

    // ML-KEM Encaps (替代 DH 密钥生成 + 共享秘密计算)
    const tEncaps0 = performance.now()
    const kemResult = await kemEncaps(challenge.pkKEM)
    this.perfMetrics.kemEncapsTime = (performance.now() - tEncaps0) * 1000

    this.kemCiphertext = kemResult.ciphertext
    this.sharedSecret = kemResult.sharedSecret

    // tagU = H(ss || uid || pk_KEM || server_sigm || ct || "clientconfirm")
    const tagU = await hash(concatBytes(
      this.sharedSecret, strToBytes(this.uid), challenge.pkKEM,
      challenge.serversigm, this.kemCiphertext, strToBytes('clientconfirm')
    ))
    this.tagU = tagU

    // sigma = Sign(skSig, (uid, pk_KEM, ct, tagU))
    const sigData = concatBytes(strToBytes(this.uid), challenge.pkKEM, this.kemCiphertext, tagU)
    const tSign0 = performance.now()
    const sigma = await ecdsaSign(this.sigKeyPair!.privateKey, sigData)
    this.perfMetrics.signTime = (performance.now() - tSign0) * 1000

    this.tau = { sigma, ct: this.kemCiphertext }

    this.logs.push({
      step: 3, title: '客户端响应 (KEM Encaps)',
      description: `ML-KEM 封装成功\nct: ${KEM_PARAMS.CT_SIZE} bytes\n生成 tagU 和签名`,
      sender: 'client',
      data: {
        'KEM Encaps': this.perfMetrics.kemEncapsTime.toFixed(0) + ' μs',
        'Sign': this.perfMetrics.signTime.toFixed(0) + ' μs',
        'ct (前32字节)': bytesToHex(this.kemCiphertext.subarray(0, 32)) + '...',
        'tagU': bytesToHex(tagU).substring(0, 32) + '...'
      },
      timeMs: performance.now() - t0,
      timestamp: new Date().toLocaleTimeString()
    })

    return { tau: this.tau, tagU }
  }

  // 步骤 5: 最终确认
  async finalize(confirmation: {
    success: boolean; tagS: Uint8Array; serversigtag: Uint8Array
  }): Promise<boolean> {
    if (!confirmation.success) return false

    // 验证服务器签名
    const sigValid = await ecdsaVerify(this.serverPubKey!, confirmation.tagS, confirmation.serversigtag)
    if (!sigValid) throw new Error('Server confirmation signature invalid')

    // 验证 tagS
    const expectedTagS = await hash(concatBytes(
      this.sharedSecret!, strToBytes(this.uid), this.tau!.sigma,
      this.peerKEMPub!, this.tagU!, strToBytes('serverconfirm')
    ))
    if (bytesToHex(expectedTagS) !== bytesToHex(confirmation.tagS)) throw new Error('tagS mismatch')

    // HKDF 密钥派生
    const tHkdf0 = performance.now()
    const hkdfSalt = concatBytes(this.peerKEMPub!, this.kemCiphertext!)
    const prk = await hkdfExtract(hkdfSalt, this.sharedSecret!)
    this.sessionKey = await hkdfExpand(prk, strToBytes('sessionkey'), 32)
    this.perfMetrics.hkdfTime = (performance.now() - tHkdf0) * 1000

    this.perfMetrics.totalAuthTime = this.perfMetrics.verifyTime + this.perfMetrics.kemEncapsTime +
      this.perfMetrics.signTime + this.perfMetrics.hkdfTime

    this.logs.push({
      step: 5, title: '双向认证成功',
      description: `服务器确认验证通过\nHKDF 会话密钥派生完成\n协议握手结束`,
      sender: 'client',
      data: {
        'Session Key': bytesToHex(this.sessionKey).substring(0, 32) + '...',
        'HKDF': this.perfMetrics.hkdfTime.toFixed(0) + ' μs',
        '总耗时': this.perfMetrics.totalAuthTime.toFixed(0) + ' μs'
      },
      timeMs: 0,
      timestamp: new Date().toLocaleTimeString()
    })

    return true
  }

  getSessionKey(): Uint8Array | null { return this.sessionKey }
}
