// ==========================================
// 后量子协议 TypeScript 类型定义
// ==========================================

export interface PQCKeyPair {
  publicKey: Uint8Array
  secretKey: Uint8Array
}

export interface KEMEncapsResult {
  ciphertext: Uint8Array
  sharedSecret: Uint8Array
}

export interface ECDHKeyPair {
  publicKey: CryptoKey
  privateKey: CryptoKey
  publicKeyRaw: Uint8Array
}

// 协议消息
export interface PQCRegistrationRequest {
  uid: string
  pkSig: Uint8Array
  skEnc: Uint8Array
}

export interface PQCAuthChallenge {
  pkKEM: Uint8Array
  serversigm: Uint8Array
  timestamp: number
  nonce: Uint8Array
}

export interface PQCAuthResponse {
  uid: string
  tau: Uint8Array
  tagU: Uint8Array
}

export interface PQCAuthConfirmation {
  success: boolean
  tagS: Uint8Array
  serversigtag: Uint8Array
}

// 性能指标
export interface PQCPerfMetrics {
  kemKeyGenTime: number
  kemEncapsTime: number
  kemDecapsTime: number
  signTime: number
  verifyTime: number
  encryptTime: number
  decryptTime: number
  hkdfTime: number
  totalAuthTime: number
  kemPublicKeySize: number
  kemCiphertextSize: number
  kemSharedSecretSize: number
}

export interface ECDHPerfMetrics {
  dhKeyGenTime: number
  ecdhComputeTime: number
  signTime: number
  verifyTime: number
  encryptTime: number
  decryptTime: number
  hkdfTime: number
  totalAuthTime: number
  dhPublicKeySize: number
  sharedSecretSize: number
}

export interface BenchmarkResult {
  method: string
  operation: string
  avgTime: number
  minTime: number
  maxTime: number
  stdDev: number
  dataSize: number
  runs: number
}

// 协议步骤日志
export interface ProtocolStep {
  step: number
  title: string
  description: string
  sender: 'client' | 'server'
  data: Record<string, string>
  timeMs: number
  timestamp: string
}

// 形式化验证结果
export interface VerificationResult {
  tool: 'ProVerif' | 'Tamarin'
  protocol: 'ECDH' | 'ML-KEM'
  properties: {
    name: string
    result: 'true' | 'false' | 'unknown'
    description: string
  }[]
}
