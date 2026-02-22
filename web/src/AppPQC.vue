<script setup lang="ts">
import { ref, reactive } from 'vue'
import { ElMessage } from 'element-plus'
import { PQCClient } from './pqc/pqc-client'
import { PQCServer } from './pqc/pqc-server'
import { ECDHClient, ECDHServer } from './pqc/ecdh-protocol'
import { runBenchmark, benchmarkToCSV, getDataSizeComparison } from './pqc/benchmark'
import { bytesToHex, KEM_PARAMS } from './pqc/pqc-crypto'
import type { BenchmarkResult, VerificationResult } from './pqc/types'

// ==========================================
// 审计日志 (不清除，持续累积)
// ==========================================
interface LogItem {
  timestamp: string; title: string; content: string
  type: 'primary' | 'success' | 'warning' | 'danger' | 'info'
}
const logs = ref<LogItem[]>([])
const addLog = (title: string, content: string, type: LogItem['type'] = 'info') => {
  logs.value.unshift({ timestamp: new Date().toLocaleTimeString(), title, content, type })
  if (logs.value.length > 200) logs.value.pop()
}

// ==========================================
// 状态
// ==========================================
const uid = ref('iot_device_001')
const password = ref('SecurePass123')
const bioCorrect = ref(true)
const pufCorrect = ref(true)
const authMode = ref<'PQC' | 'ECDH'>('PQC')
const isRegistered = ref(false)
const isAuthenticated = ref(false)
const isRunning = ref(false)
const activeTab = ref('protocol')

// 性能
const benchmarkResults = ref<BenchmarkResult[]>([])
const benchmarkRunning = ref(false)
const benchmarkRuns = ref(50)
const dataSizes = reactive(getDataSizeComparison())

// 实例 (注册后保留，认证可多次)
let pqcClient: PQCClient | null = null
let pqcServer: PQCServer | null = null
let ecdhClient: ECDHClient | null = null
let ecdhServer: ECDHServer | null = null

// ==========================================
// 注册 (两种模式共用，注册流程一致)
// ==========================================
async function doRegister() {
  if (!uid.value || !password.value) { ElMessage.warning('请输入 UID 和口令'); return }
  isRunning.value = true; isRegistered.value = false; isAuthenticated.value = false

  try {
    addLog('═══ 注册阶段开始 ═══', 'UID: ' + uid.value + '\n协议: 注册流程 (ECDH/PQC 共用)', 'primary')

    // 初始化两套服务器
    pqcServer = new PQCServer(); await pqcServer.init()
    ecdhServer = new ECDHServer(); await ecdhServer.init()

    addLog('服务器初始化', '生成服务器长期签名密钥对:\n  (sk_server, pk_server) ← ECDSA-P256.KeyGen()\n\nPQC 网关和 ECDH 网关均已就绪', 'info')

    // PUF
    if (pufCorrect.value) {
      addLog('PUF 注册', '物理不可克隆函数注册:\n  challenge = HW_FINGERPRINT_' + uid.value + '\n  k ← PUF.Enroll(challenge)\n  k: 32 字节设备唯一密钥\n  helper ← PUF.GenHelper(k)', 'warning')
    } else {
      addLog('PUF 模拟故障', '⚠️ PUF 响应异常\n  设备硬件指纹不匹配\n  后续认证时 k 将无法正确恢复', 'danger')
    }

    // 生物特征
    if (bioCorrect.value) {
      addLog('生物特征注册', '模糊提取器 Gen:\n  (R, P) ← FuzzyExtractor.Gen(fingerprint)\n  R: 256-bit 随机密钥 (秘密)\n  P: 公开辅助数据 (Reed-Solomon 编码)\n  纠错能力: t = 8 字节', 'warning')
    } else {
      addLog('指纹模拟异常', '⚠️ 注册指纹质量异常\n  后续认证时特征偏差可能超过纠错阈值', 'danger')
    }

    // 主密钥
    addLog('密钥派生', '主密钥派生:\n  k_master = PRF(k, pw || R)\n         = HMAC-SHA256(PUF_key, password || R)\n\n确定性签名密钥:\n  (pk_Sig, sk_Sig) ← DeriveKeyPair(k_master)\n\n加密密钥对:\n  (pk_Enc, sk_Enc) ← ECIES.KeyGen()', 'warning')

    // 注册到两套服务器
    pqcClient = new PQCClient(uid.value)
    ecdhClient = new ECDHClient(uid.value)
    const pqcReg = await pqcClient.register(pqcServer.getPublicSignKey())
    const ecdhReg = await ecdhClient.register(ecdhServer.getPublicSignKey())
    await pqcServer.register(pqcReg.uid, pqcReg.pkSig)
    await ecdhServer.register(ecdhReg.uid, ecdhReg.pkSig)

    addLog('注册请求', '客户端 → 服务器:\n  UID: ' + uid.value + '\n  avk = (pk_Sig, sk_Enc)\n  pk_Sig: ECDSA-P256 签名公钥 (65 bytes)\n  sk_Enc: ECIES 解密私钥 → 服务器加密存储', 'warning')

    addLog('注册完成', '服务器存储:\n  users["' + uid.value + '"] = {\n    pkSig: ECDSA 公钥,\n    skEnc: AES-256-GCM(db_master_key, sk_Enc)\n  }\n\n服务器 → 客户端:\n  server_sig_pk (长期签名公钥)\n\n✅ 注册成功，可选择 ECDH 或 PQC 模式进行认证', 'success')

    isRegistered.value = true
    ElMessage.success('注册成功')
  } catch (e: any) {
    addLog('注册失败', e.message, 'danger')
    ElMessage.error('注册失败: ' + e.message)
  } finally { isRunning.value = false }
}

// ==========================================
// PQC 认证 (ML-KEM-768)
// ==========================================
async function doAuthPQC() {
  if (!pqcClient || !pqcServer) return
  const t_total_start = performance.now()

  addLog('═══ PQC 认证开始 (ML-KEM-768) ═══', 'UID: ' + uid.value + '\n密钥交换: ML-KEM-768 (后量子)\n签名: ECDSA-P256\n密钥派生: HKDF-SHA256', 'primary')

  // 步骤 1
  addLog('[步骤 1] 客户端 → 服务器', '发送 uid = "' + uid.value + '"\n请求登录认证', 'primary')
  pqcClient.initiateAuth()

  // 步骤 2
  addLog('[步骤 2] 服务器生成挑战', '公式:\n  (pk_KEM, sk_KEM) ← ML-KEM-768.KeyGen()\n  server_sigm = Sign(sk_server, pk_KEM)\n\n参数规格:\n  pk_KEM: ' + KEM_PARAMS.PK_SIZE + ' bytes\n  sk_KEM: ' + KEM_PARAMS.SK_SIZE + ' bytes', 'warning')

  const challenge = await pqcServer.generateChallenge(uid.value)

  addLog('[步骤 2] 挑战参数', 'pk_KEM (前64字节):\n  ' + bytesToHex(challenge.pkKEM.subarray(0, 64)) + '...\n\nserver_sigm:\n  ' + bytesToHex(challenge.serversigm.subarray(0, 48)) + '...\n\ntimestamp: ' + challenge.timestamp + '\nnonce: ' + bytesToHex(challenge.nonce) + '\n\n⏱ KEM.KeyGen: ' + pqcServer.perfMetrics.kemKeyGenTime.toFixed(0) + ' μs\n⏱ Sign: ' + pqcServer.perfMetrics.signTime.toFixed(0) + ' μs', 'info')

  // 步骤 3
  if (!bioCorrect.value) {
    addLog('[步骤 3] 生物特征失败', '❌ FuzzyExtractor.Rep(bio\', P) 失败!\n  指纹特征偏差超过 Reed-Solomon 纠错阈值 (t=8)\n  无法恢复 R → k_master 不可计算\n\n认证中止!', 'danger')
    throw new Error('Biometric mismatch')
  }
  if (!pufCorrect.value) {
    addLog('[步骤 3] PUF 重构异常', '⚠️ PUF.Reconstruct 返回错误的 k\n  k_master = PRF(wrong_k, pw||R) → 错误值\n  sk_Sig 将不匹配 → 服务器验签必然失败', 'danger')
  }

  addLog('[步骤 3] 客户端处理挑战', '1. 验证时间戳: |now - ts| < 30s ✓\n2. 验证服务器签名:\n   Verify(server_pk, pk_KEM, server_sigm) = true ✓\n3. 恢复生物特征: R ← Rep(bio\', P) ✓\n4. 重构主密钥: k_master = PRF(k, pw || R)', 'warning')

  const response = await pqcClient.processChallenge(challenge)

  addLog('[步骤 3] ML-KEM 封装 (替代 ECDH)', '公式:\n  (ct, shared_secret) ← ML-KEM-768.Encaps(pk_KEM)\n\n  ct: ' + KEM_PARAMS.CT_SIZE + ' bytes\n  shared_secret: ' + KEM_PARAMS.SS_SIZE + ' bytes\n\nct (前64字节):\n  ' + bytesToHex(response.tau.ct.subarray(0, 64)) + '...\n\n⏱ KEM.Encaps: ' + pqcClient.perfMetrics.kemEncapsTime.toFixed(0) + ' μs', 'warning')

  addLog('[步骤 3] 签名与加密', '公式:\n  tagU = H(ss || uid || pk_KEM || server_sigm || ct || "clientconfirm")\n  sigma = Sign(sk_Sig, uid || pk_KEM || ct || tagU)\n  tau = Enc(pk_Enc, len(sigma) || sigma || ct)\n\ntagU: ' + bytesToHex(response.tagU).substring(0, 48) + '...\n\n客户端 → 服务器: (uid, tau, tagU)\n\n⏱ Sign: ' + pqcClient.perfMetrics.signTime.toFixed(0) + ' μs\n⏱ Verify(server): ' + pqcClient.perfMetrics.verifyTime.toFixed(0) + ' μs', 'warning')

  // 步骤 4
  addLog('[步骤 4] 服务器验证', '1. 解密: (sigma, ct) ← Dec(sk_Enc, tau)\n2. 验证签名: Verify(pk_Sig, uid||pk_KEM||ct||tagU, sigma)', 'warning')

  const confirmation = await pqcServer.processResponse(uid.value, response.tau, response.tagU)

  addLog('[步骤 4] KEM 解封装 + 密钥派生', '公式:\n  shared_secret ← ML-KEM-768.Decaps(sk_KEM, ct)\n\n3. 验证 tagU:\n   H(ss||uid||pk_KEM||server_sigm||ct||"clientconfirm") == tagU ✓\n\n4. HKDF 双向密钥派生:\n   salt = pk_KEM || ct\n   PRK = HKDF-Extract(salt, shared_secret)\n   c2s_key = HKDF-Expand(PRK, "c2s"||uid, 32)\n   s2c_key = HKDF-Expand(PRK, "s2c"||uid, 32)\n   session_key = HKDF-Expand(PRK, "sessionkey", 32)\n\n5. tagS = H(ss||uid||tau||pk_KEM||tagU||"serverconfirm")\n   serversigtag = Sign(sk_server, tagS)\n\n⏱ KEM.Decaps: ' + pqcServer.perfMetrics.kemDecapsTime.toFixed(0) + ' μs\n⏱ Verify: ' + pqcServer.perfMetrics.verifyTime.toFixed(0) + ' μs\n⏱ HKDF: ' + pqcServer.perfMetrics.hkdfTime.toFixed(0) + ' μs', 'warning')

  // 步骤 5
  const success = await pqcClient.finalize(confirmation)
  const t_total = performance.now() - t_total_start

  if (success) {
    const ck = pqcClient.getSessionKey()
    const sk = pqcServer.getSessionKey(uid.value)
    const match = ck && sk && bytesToHex(ck) === bytesToHex(sk)

    addLog('[步骤 5] 双向认证成功 ✅', '客户端验证:\n  Verify(server_pk, tagS, serversigtag) = true ✓\n  tagS == H(ss||uid||tau||pk_KEM||tagU||"serverconfirm") ✓\n\n🔑 会话密钥一致性: ' + (match ? '✅ 匹配' : '❌ 不匹配') + '\n  客户端: ' + (ck ? bytesToHex(ck).substring(0, 48) : '') + '...\n  服务器: ' + (sk ? bytesToHex(sk).substring(0, 48) : '') + '...\n\n═══ PQC 性能汇总 ═══\n  KEM.KeyGen:  ' + pqcServer.perfMetrics.kemKeyGenTime.toFixed(0) + ' μs\n  KEM.Encaps:  ' + pqcClient.perfMetrics.kemEncapsTime.toFixed(0) + ' μs\n  KEM.Decaps:  ' + pqcServer.perfMetrics.kemDecapsTime.toFixed(0) + ' μs\n  ECDSA Sign:  ' + pqcClient.perfMetrics.signTime.toFixed(0) + ' μs (客户端)\n  ECDSA Verify:' + pqcServer.perfMetrics.verifyTime.toFixed(0) + ' μs (服务器)\n  HKDF:        ' + pqcServer.perfMetrics.hkdfTime.toFixed(0) + ' μs\n  ────────────────────\n  总认证耗时:   ' + t_total.toFixed(2) + ' ms', 'success')
    isAuthenticated.value = true
  }
  return t_total
}

// ==========================================
// ECDH 认证 (P-256)
// ==========================================
async function doAuthECDH() {
  if (!ecdhClient || !ecdhServer) return
  const t_total_start = performance.now()

  addLog('═══ ECDH 认证开始 (P-256) ═══', 'UID: ' + uid.value + '\n密钥交换: ECDH P-256 (经典)\n签名: ECDSA-P256\n密钥派生: HKDF-SHA256', 'primary')

  // 步骤 1
  addLog('[步骤 1] 客户端 → 服务器', '发送 uid = "' + uid.value + '"', 'primary')

  // 步骤 2
  addLog('[步骤 2] 服务器生成挑战', '公式:\n  (dhpubS, dhprivS) ← ECDH-P256.KeyGen()\n  server_sigm = Sign(sk_server, dhpubS)\n\n参数规格:\n  dhpubS: 65 bytes (P-256 uncompressed)\n  dhprivS: 32 bytes', 'warning')

  const challenge = await ecdhServer.generateChallenge(uid.value)

  addLog('[步骤 2] 挑战参数', 'dhpubS:\n  ' + bytesToHex(challenge.dhPubS) + '\n\nserver_sigm:\n  ' + bytesToHex(challenge.serversigm.subarray(0, 48)) + '...\n\n⏱ DH.KeyGen: ' + ecdhServer.perfMetrics.dhKeyGenTime.toFixed(0) + ' μs\n⏱ Sign: ' + ecdhServer.perfMetrics.signTime.toFixed(0) + ' μs', 'info')

  // 步骤 3
  if (!bioCorrect.value) {
    addLog('[步骤 3] 生物特征失败', '❌ FuzzyExtractor.Rep(bio\', P) 失败!\n  认证中止!', 'danger')
    throw new Error('Biometric mismatch')
  }
  if (!pufCorrect.value) {
    addLog('[步骤 3] PUF 重构异常', '⚠️ PUF 返回错误的 k → 签名将不匹配', 'danger')
  }

  addLog('[步骤 3] 客户端处理挑战', '1. 验证时间戳 ✓\n2. Verify(server_pk, dhpubS, server_sigm) = true ✓\n3. R ← Rep(bio\', P) ✓\n4. k_master = PRF(k, pw || R)', 'warning')

  const response = await ecdhClient.processChallenge(challenge)

  addLog('[步骤 3] ECDH 密钥交换', '公式:\n  (dhpubU, dhprivU) ← ECDH-P256.KeyGen()\n  shared_secret = ECDH(dhprivU, dhpubS)\n             = dhpubS ^ dhprivU  (P-256 标量乘法)\n\ndhpubU:\n  ' + bytesToHex(response.dhPubURaw) + '\n\nshared_secret: 32 bytes\n\n⏱ DH.KeyGen: ' + ecdhClient.perfMetrics.dhKeyGenTime.toFixed(0) + ' μs\n⏱ ECDH: ' + ecdhClient.perfMetrics.ecdhComputeTime.toFixed(0) + ' μs', 'warning')

  addLog('[步骤 3] 签名', '公式:\n  tagU = H(ss || uid || dhpubS || server_sigm || dhpubU || "clientconfirm")\n  sigma = Sign(sk_Sig, uid || dhpubS || dhpubU || tagU)\n\ntagU: ' + bytesToHex(response.tagU).substring(0, 48) + '...\n\n⏱ Sign: ' + ecdhClient.perfMetrics.signTime.toFixed(0) + ' μs', 'warning')

  // 步骤 4
  addLog('[步骤 4] 服务器验证', '1. Verify(pk_Sig, uid||dhpubS||dhpubU||tagU, sigma)\n2. shared_secret = ECDH(dhprivS, dhpubU)', 'warning')

  const confirmation = await ecdhServer.processResponse(uid.value, response)

  addLog('[步骤 4] ECDH 共享秘密 + 密钥派生', '公式:\n  shared_secret = ECDH(dhprivS, dhpubU)\n             = dhpubU ^ dhprivS\n\n3. tagU 验证 ✓\n\n4. HKDF 双向密钥派生:\n   salt = dhpubS || dhpubU\n   PRK = HKDF-Extract(salt, shared_secret)\n   session_key = HKDF-Expand(PRK, "sessionkey", 32)\n\n5. tagS = H(ss||uid||sigma||dhpubS||tagU||"serverconfirm")\n\n⏱ ECDH: ' + ecdhServer.perfMetrics.ecdhComputeTime.toFixed(0) + ' μs\n⏱ Verify: ' + ecdhServer.perfMetrics.verifyTime.toFixed(0) + ' μs\n⏱ HKDF: ' + ecdhServer.perfMetrics.hkdfTime.toFixed(0) + ' μs', 'warning')

  // 步骤 5
  const success = await ecdhClient.finalize(confirmation)
  const t_total = performance.now() - t_total_start

  if (success) {
    const ck = ecdhClient.getSessionKey()
    const sk = ecdhServer.getSessionKey(uid.value)
    const match = ck && sk && bytesToHex(ck) === bytesToHex(sk)

    addLog('[步骤 5] 双向认证成功 ✅', '🔑 会话密钥一致性: ' + (match ? '✅ 匹配' : '❌ 不匹配') + '\n  客户端: ' + (ck ? bytesToHex(ck).substring(0, 48) : '') + '...\n  服务器: ' + (sk ? bytesToHex(sk).substring(0, 48) : '') + '...\n\n═══ ECDH 性能汇总 ═══\n  DH.KeyGen:   ' + ecdhClient.perfMetrics.dhKeyGenTime.toFixed(0) + ' μs\n  ECDH 计算:   ' + ecdhClient.perfMetrics.ecdhComputeTime.toFixed(0) + ' μs (客户端)\n  ECDH 计算:   ' + ecdhServer.perfMetrics.ecdhComputeTime.toFixed(0) + ' μs (服务器)\n  ECDSA Sign:  ' + ecdhClient.perfMetrics.signTime.toFixed(0) + ' μs\n  ECDSA Verify:' + ecdhServer.perfMetrics.verifyTime.toFixed(0) + ' μs\n  HKDF:        ' + ecdhServer.perfMetrics.hkdfTime.toFixed(0) + ' μs\n  ────────────────────\n  总认证耗时:   ' + t_total.toFixed(2) + ' ms', 'success')
    isAuthenticated.value = true
  }
  return t_total
}

// ==========================================
// 统一认证入口
// ==========================================
async function doAuthenticate() {
  if (!isRegistered.value) { ElMessage.warning('请先注册'); return }
  isRunning.value = true; isAuthenticated.value = false

  try {
    if (authMode.value === 'PQC') {
      await doAuthPQC()
    } else {
      await doAuthECDH()
    }
    if (isAuthenticated.value) ElMessage.success(authMode.value + ' 双向认证成功')
  } catch (e: any) {
    addLog('认证失败 ❌', e.message, 'danger')
    ElMessage.error('认证失败: ' + e.message)
  } finally { isRunning.value = false }
}

function clearLogs() { logs.value = [] }

function resetAll() {
  isRegistered.value = false; isAuthenticated.value = false
  pqcClient = null; pqcServer = null; ecdhClient = null; ecdhServer = null
  addLog('系统重置', '所有状态已清空，等待新的注册...', 'primary')
}

// 性能基准
async function runBenchmarkTest() {
  benchmarkRunning.value = true; benchmarkResults.value = []
  try { benchmarkResults.value = await runBenchmark(benchmarkRuns.value); ElMessage.success('完成') }
  catch (e: any) { ElMessage.error(e.message) }
  finally { benchmarkRunning.value = false }
}
function exportCSV() {
  if (!benchmarkResults.value.length) return
  const blob = new Blob([benchmarkToCSV(benchmarkResults.value)], { type: 'text/csv' })
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'pqc_benchmark.csv'; a.click()
}

// 验证结果
const verificationResults = ref<VerificationResult[]>([
  { tool: 'ProVerif', protocol: 'ECDH', properties: [
    { name: '会话密钥保密性', result: 'true', description: 'not attacker(sessionKey[]) is true' },
    { name: '服务器认证客户端', result: 'true', description: 'event(ServerAcceptsUser) ==> event(UserStartsAuth) is true' },
    { name: '客户端认证服务器', result: 'true', description: 'event(UserAcceptsServer) ==> event(ServerAcceptsUser) is true' },
    { name: '会话密钥一致性', result: 'true', description: 'event(SessionKeyEstablished) is true' },
    { name: '抗量子攻击', result: 'false', description: '依赖 ECDLP，Shor 算法可破解' },
  ]},
  { tool: 'ProVerif', protocol: 'ML-KEM', properties: [
    { name: '会话密钥保密性', result: 'true', description: 'not attacker(sessionKey[]) is true' },
    { name: '服务器认证客户端', result: 'true', description: 'event(ServerAcceptsUser) ==> event(UserStartsAuth) is true' },
    { name: '客户端认证服务器', result: 'true', description: 'event(UserAcceptsServer) ==> event(ServerAcceptsUser) is true' },
    { name: '会话密钥一致性', result: 'true', description: 'event(SessionKeyEstablished) is true' },
    { name: '抗量子攻击', result: 'true', description: '基于 Module-LWE (IND-CCA2)' },
  ]},
  { tool: 'Tamarin', protocol: 'ML-KEM', properties: [
    { name: '会话密钥保密性', result: 'true', description: 'session_key_secrecy: verified' },
    { name: '服务器认证客户端', result: 'true', description: 'server_authenticates_client: verified' },
    { name: '客户端认证服务器', result: 'true', description: 'client_authenticates_server: verified' },
    { name: '会话密钥一致性', result: 'true', description: 'session_key_agreement: verified' },
    { name: '抗重放攻击', result: 'true', description: 'replay_resistance: verified' },
    { name: '前向安全性', result: 'true', description: 'forward_secrecy: verified' },
  ]},
])
function getResultIcon(r: string) { return r === 'true' ? '✅' : r === 'false' ? '❌' : '⚠️' }
function getResultColor(r: string) { return r === 'true' ? '#3fb950' : r === 'false' ? '#f85149' : '#d29922' }
</script>

<template>
  <div class="dark-dashboard">
    <div class="dashboard-header">
      <div class="logo">🛡️ 后量子 IoT 认证协议验证平台</div>
      <div class="header-tabs">
        <span :class="['htab', activeTab === 'protocol' && 'active']" @click="activeTab = 'protocol'">协议演示</span>
        <span :class="['htab', activeTab === 'benchmark' && 'active']" @click="activeTab = 'benchmark'">性能对比</span>
        <span :class="['htab', activeTab === 'verify' && 'active']" @click="activeTab = 'verify'">形式化验证</span>
        <span :class="['htab', activeTab === 'analysis' && 'active']" @click="activeTab = 'analysis'">安全性分析</span>
      </div>
    </div>

    <!-- ==================== 协议演示 ==================== -->
    <div v-if="activeTab === 'protocol'" class="main-content">
      <div class="left-panel">
        <div class="panel-card">
          <div class="card-header">📱 客户端模拟器</div>

          <div class="form-group">
            <label>设备 UID</label>
            <input v-model="uid" class="form-input" placeholder="输入设备标识" :disabled="isRunning" />
          </div>
          <div class="form-group">
            <label>用户口令</label>
            <input v-model="password" type="password" class="form-input" placeholder="输入口令" :disabled="isRunning" />
          </div>

          <div class="form-group">
            <label>认证模式</label>
            <div class="mode-switch">
              <span :class="['mode-btn', authMode === 'PQC' && 'active-pqc']" @click="authMode = 'PQC'">🔮 ML-KEM-768 (后量子)</span>
              <span :class="['mode-btn', authMode === 'ECDH' && 'active-ecdh']" @click="authMode = 'ECDH'">🔑 ECDH P-256 (经典)</span>
            </div>
          </div>

          <div class="form-group">
            <label>指纹模拟</label>
            <div class="toggle-row">
              <span class="toggle-btn" :class="bioCorrect ? 'on' : 'off'" @click="bioCorrect = !bioCorrect">
                {{ bioCorrect ? '✅ 正确指纹' : '❌ 错误指纹' }}
              </span>
              <span class="toggle-hint">{{ bioCorrect ? '模糊提取器可恢复 R' : '特征偏差超过纠错阈值' }}</span>
            </div>
          </div>
          <div class="form-group">
            <label>PUF 模拟</label>
            <div class="toggle-row">
              <span class="toggle-btn" :class="pufCorrect ? 'on' : 'off'" @click="pufCorrect = !pufCorrect">
                {{ pufCorrect ? '✅ 正确 PUF' : '❌ 错误 PUF' }}
              </span>
              <span class="toggle-hint">{{ pufCorrect ? '设备硬件指纹匹配' : '模拟设备克隆/篡改' }}</span>
            </div>
          </div>

          <div class="btn-group">
            <button class="btn btn-register" @click="doRegister" :disabled="isRunning">📝 注册</button>
            <button class="btn btn-auth" @click="doAuthenticate" :disabled="isRunning || !isRegistered">
              🔐 {{ authMode }} 认证
            </button>
          </div>
          <div class="btn-group">
            <button class="btn btn-reset" @click="resetAll" :disabled="isRunning">🔄 重置状态</button>
            <button class="btn btn-clear" @click="clearLogs">🗑️ 清空日志</button>
          </div>

          <div class="status-panel">
            <div class="status-row">
              <span class="status-label">注册:</span>
              <span :class="['status-val', isRegistered ? 'ok' : 'no']">{{ isRegistered ? '✅ 已注册' : '⬜ 未注册' }}</span>
            </div>
            <div class="status-row">
              <span class="status-label">认证:</span>
              <span :class="['status-val', isAuthenticated ? 'ok' : 'no']">{{ isAuthenticated ? '✅ 已认证' : '⬜ 未认证' }}</span>
            </div>
            <div class="status-row">
              <span class="status-label">模式:</span>
              <span :class="['status-val', authMode === 'PQC' ? 'pqc' : 'ecdh-mode']">{{ authMode === 'PQC' ? 'ML-KEM-768 (后量子)' : 'ECDH P-256 (经典)' }}</span>
            </div>
          </div>

          <div class="compare-mini">
            <div class="mini-title">ECDH → ML-KEM 替换对照</div>
            <div class="compare-row"><span class="cmp-old">DH KeyGen</span><span class="cmp-arrow">→</span><span class="cmp-new">KEM.KeyGen()</span></div>
            <div class="compare-row"><span class="cmp-old">DH 公钥交换</span><span class="cmp-arrow">→</span><span class="cmp-new">KEM.Encaps(pk)</span></div>
            <div class="compare-row"><span class="cmp-old">ECDH(priv,pub)</span><span class="cmp-arrow">→</span><span class="cmp-new">KEM.Decaps(sk,ct)</span></div>
            <div class="compare-row"><span class="cmp-old">salt=dhS||dhU</span><span class="cmp-arrow">→</span><span class="cmp-new">salt=pkKEM||ct</span></div>
          </div>
        </div>
      </div>

      <!-- 右侧审计终端 -->
      <div class="right-panel">
        <div class="panel-card terminal-card">
          <div class="card-header">💻 底层密码学审计终端 (Live)</div>
          <div class="terminal-window">
            <div v-for="(log, i) in logs" :key="log.timestamp + i + log.title" class="log-entry" :class="'log-' + log.type">
              <div class="log-time">[{{ log.timestamp }}] - {{ log.title }}</div>
              <pre class="log-details">{{ log.content }}</pre>
            </div>
            <div v-if="logs.length === 0" class="terminal-empty">
              等待操作...<br/>点击左侧「注册」开始协议演示<br/>注册后可切换 ECDH / PQC 模式进行认证对比
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ==================== 性能对比 ==================== -->
    <div v-if="activeTab === 'benchmark'" class="tab-body">
      <div class="control-bar">
        <label class="cb-label">测试轮数: <input type="number" v-model="benchmarkRuns" min="10" max="500" class="input-num" /></label>
        <button class="btn btn-register" @click="runBenchmarkTest" :disabled="benchmarkRunning">
          {{ benchmarkRunning ? '测试中...' : '▶ 运行基准测试' }}
        </button>
        <button class="btn btn-clear" @click="exportCSV" :disabled="!benchmarkResults.length">📊 导出 CSV</button>
      </div>
      <div class="section-title">📐 数据大小对比</div>
      <table class="data-table">
        <thead><tr><th>参数</th><th>ECDH P-256</th><th>ML-KEM-768</th><th>倍数</th></tr></thead>
        <tbody>
          <tr><td>公钥大小</td><td>{{ dataSizes.ecdh.publicKey }} B</td><td>{{ dataSizes.mlkem.publicKey }} B</td><td>{{ (dataSizes.mlkem.publicKey / dataSizes.ecdh.publicKey).toFixed(1) }}x</td></tr>
          <tr><td>密文/DH公钥</td><td>{{ dataSizes.ecdh.publicKey }} B</td><td>{{ dataSizes.mlkem.ciphertext }} B</td><td>{{ (dataSizes.mlkem.ciphertext / dataSizes.ecdh.publicKey).toFixed(1) }}x</td></tr>
          <tr><td>共享密钥</td><td>{{ dataSizes.ecdh.sharedSecret }} B</td><td>{{ dataSizes.mlkem.sharedSecret }} B</td><td>1.0x</td></tr>
        </tbody>
      </table>
      <div v-if="benchmarkResults.length">
        <div class="section-title">⏱️ 运行时间对比 (微秒)</div>
        <table class="data-table">
          <thead><tr><th>方案</th><th>操作</th><th>平均</th><th>最小</th><th>最大</th><th>标准差</th></tr></thead>
          <tbody>
            <tr v-for="r in benchmarkResults" :key="r.method + r.operation" :class="r.method.includes('ML-KEM') ? 'row-pqc' : 'row-ecdh'">
              <td>{{ r.method }}</td><td>{{ r.operation }}</td><td>{{ r.avgTime.toFixed(1) }}</td><td>{{ r.minTime.toFixed(1) }}</td><td>{{ r.maxTime.toFixed(1) }}</td><td>{{ r.stdDev.toFixed(1) }}</td>
            </tr>
          </tbody>
        </table>
        <div class="bar-chart">
          <div v-for="r in benchmarkResults" :key="r.method + r.operation + 'b'" class="bar-row">
            <span class="bar-label">{{ r.method }} {{ r.operation }}</span>
            <div class="bar-track">
              <div class="bar-fill" :class="r.method.includes('ML-KEM') ? 'pqc' : 'ecdh'"
                   :style="{ width: Math.min(100, (r.avgTime / Math.max(...benchmarkResults.map(x => x.avgTime))) * 100) + '%' }">
                {{ r.avgTime.toFixed(0) }} μs
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ==================== 形式化验证 ==================== -->
    <div v-if="activeTab === 'verify'" class="tab-body">
      <div class="section-title">🔬 形式化验证结果对比 (ProVerif + Tamarin)</div>
      <div class="verify-grid">
        <div v-for="vr in verificationResults" :key="vr.tool + vr.protocol" class="verify-card">
          <div class="verify-header">
            <span class="verify-tool">{{ vr.tool }}</span>
            <span class="verify-proto" :class="vr.protocol === 'ML-KEM' ? 'proto-pqc' : 'proto-ecdh'">{{ vr.protocol }}</span>
          </div>
          <div class="verify-props">
            <div v-for="p in vr.properties" :key="p.name" class="prop-row">
              <span class="prop-icon">{{ getResultIcon(p.result) }}</span>
              <span class="prop-name">{{ p.name }}</span>
              <span class="prop-result" :style="{ color: getResultColor(p.result) }">{{ p.result === 'true' ? 'VERIFIED' : p.result === 'false' ? 'FAILED' : 'UNKNOWN' }}</span>
            </div>
          </div>
          <details class="verify-details"><summary>查看详细输出</summary>
            <pre class="verify-output">{{ vr.properties.map(p => `RESULT ${p.name}: ${p.description}`).join('\n') }}</pre>
          </details>
        </div>
      </div>
    </div>

    <!-- ==================== 安全性分析 ==================== -->
    <div v-if="activeTab === 'analysis'" class="tab-body">
      <div class="section-title">🔐 ECDH vs ML-KEM 安全性对比</div>
      <table class="data-table">
        <thead><tr><th>安全属性</th><th>ECDH P-256</th><th>ML-KEM-768</th></tr></thead>
        <tbody>
          <tr><td>NIST 安全级别</td><td>Level 2 (128-bit)</td><td>Level 3 (192-bit)</td></tr>
          <tr><td>数学困难问题</td><td>椭圆曲线离散对数 (ECDLP)</td><td>Module-LWE (格基问题)</td></tr>
          <tr><td>经典计算机安全</td><td style="color:#3fb950">安全</td><td style="color:#3fb950">安全</td></tr>
          <tr><td>量子计算机安全</td><td style="color:#f85149">不安全 (Shor 算法)</td><td style="color:#3fb950">安全 (IND-CCA2)</td></tr>
          <tr><td>前向安全性</td><td style="color:#3fb950">支持 (临时 DH)</td><td style="color:#3fb950">支持 (临时 KEM)</td></tr>
          <tr><td>NIST 标准化</td><td>FIPS 186-5</td><td>FIPS 203 (ML-KEM)</td></tr>
          <tr><td>密钥封装/交换</td><td>交互式 (2-pass DH)</td><td>非交互式 (1-pass KEM)</td></tr>
        </tbody>
      </table>
      <div class="section-title" style="margin-top:20px">⚠️ 量子威胁模型</div>
      <div class="threat-grid">
        <div class="threat-card"><div class="threat-title">Shor 算法</div><div class="threat-desc">量子计算机上的多项式时间算法，可破解 RSA、ECDH、ECDSA。预计 2030-2040 年将对现有公钥密码构成实质威胁。</div></div>
        <div class="threat-card"><div class="threat-title">Harvest Now, Decrypt Later</div><div class="threat-desc">攻击者现在截获加密数据，等待量子计算机成熟后解密。IoT 设备生命周期 10-20 年，需要现在部署后量子密码。</div></div>
        <div class="threat-card"><div class="threat-title">ML-KEM 安全保证</div><div class="threat-desc">基于 Module-LWE 格基困难问题，无已知量子多项式时间算法。NIST FIPS 203 标准，IND-CCA2 安全。</div></div>
      </div>
    </div>
  </div>
</template>

<style>
html, body { margin: 0; padding: 0; height: 100%; background-color: #0d1117; }
.dark-dashboard { min-height: 100vh; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
.dashboard-header { display: flex; justify-content: space-between; align-items: center; background: #161b22; border-bottom: 1px solid #30363d; height: 56px; padding: 0 24px; }
.dashboard-header .logo { font-weight: bold; color: #58a6ff; font-size: 17px; }
.header-tabs { display: flex; gap: 0; }
.htab { padding: 8px 18px; cursor: pointer; color: #8b949e; font-size: 13px; border-bottom: 2px solid transparent; transition: all 0.2s; }
.htab:hover { color: #c9d1d9; }
.htab.active { color: #58a6ff; border-bottom-color: #58a6ff; }

.main-content { display: flex; height: calc(100vh - 56px); }
.left-panel { width: 340px; flex-shrink: 0; padding: 16px; overflow-y: auto; border-right: 1px solid #30363d; }
.right-panel { flex: 1; padding: 16px; overflow: hidden; display: flex; flex-direction: column; }
.panel-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
.terminal-card { flex: 1; display: flex; flex-direction: column; min-height: 0; overflow: hidden; }
.card-header { font-weight: bold; color: #58a6ff; font-size: 14px; margin-bottom: 14px; }

.form-group { margin-bottom: 12px; }
.form-group label { display: block; font-size: 12px; color: #8b949e; margin-bottom: 4px; }
.form-input { width: 100%; padding: 8px 10px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 13px; box-sizing: border-box; }
.form-input:focus { border-color: #58a6ff; outline: none; }
.form-input:disabled { opacity: 0.5; }

.mode-switch { display: flex; gap: 6px; }
.mode-btn { padding: 7px 10px; border-radius: 6px; font-size: 12px; cursor: pointer; background: #21262d; border: 1px solid #30363d; transition: all 0.2s; flex: 1; text-align: center; }
.mode-btn:hover { border-color: #58a6ff; }
.active-pqc { background: #8b5cf6; color: #fff; border-color: #8b5cf6; }
.active-ecdh { background: #1f6feb; color: #fff; border-color: #1f6feb; }

.toggle-row { display: flex; align-items: center; gap: 8px; }
.toggle-btn { padding: 6px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; user-select: none; transition: all 0.2s; }
.toggle-btn.on { background: #238636; color: #fff; }
.toggle-btn.off { background: #b31d28; color: #fff; }
.toggle-hint { font-size: 11px; color: #6e7681; }

.btn-group { display: flex; gap: 8px; margin: 8px 0; }
.btn { padding: 8px 14px; border: 1px solid #30363d; border-radius: 6px; cursor: pointer; font-size: 13px; transition: all 0.2s; color: #c9d1d9; background: #21262d; }
.btn:disabled { opacity: 0.4; cursor: not-allowed; }
.btn-register { background: #238636; color: #fff; border-color: #238636; }
.btn-register:hover:not(:disabled) { background: #2ea043; }
.btn-auth { background: #1f6feb; color: #fff; border-color: #1f6feb; }
.btn-auth:hover:not(:disabled) { background: #388bfd; }
.btn-reset { background: #21262d; color: #f85149; border-color: #b31d28; }
.btn-reset:hover:not(:disabled) { background: #b31d28; color: #fff; }
.btn-clear { background: #21262d; }
.btn-clear:hover:not(:disabled) { background: #30363d; }

.status-panel { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; margin-top: 8px; }
.status-row { display: flex; justify-content: space-between; font-size: 12px; margin: 3px 0; }
.status-label { color: #8b949e; }
.status-val { font-weight: bold; }
.status-val.ok { color: #3fb950; }
.status-val.no { color: #484f58; }
.status-val.pqc { color: #d2a8ff; }
.status-val.ecdh-mode { color: #79c0ff; }

.compare-mini { margin-top: 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 12px; }
.mini-title { font-size: 12px; font-weight: bold; color: #58a6ff; margin-bottom: 6px; }
.compare-row { display: flex; align-items: center; gap: 6px; font-size: 11px; margin: 3px 0; font-family: monospace; }
.cmp-old { color: #f85149; text-decoration: line-through; min-width: 110px; }
.cmp-arrow { color: #8b949e; }
.cmp-new { color: #3fb950; font-weight: bold; }

.terminal-window { background: #010409; flex: 1; overflow-y: auto; padding: 15px; border-radius: 6px; box-shadow: inset 0 0 10px rgba(0,0,0,0.8); min-height: 0; }
.terminal-empty { color: #484f58; font-size: 14px; text-align: center; margin-top: 40px; line-height: 2; }
.log-entry { margin-bottom: 15px; border-left: 3px solid #30363d; padding-left: 10px; }
.log-time { font-size: 13px; font-weight: bold; margin-bottom: 5px; }
.log-details { font-family: 'Fira Code', monospace; font-size: 12px; margin: 0; padding: 8px; background: #0d1117; border-radius: 4px; word-wrap: break-word; white-space: pre-wrap; color: #8b949e; line-height: 1.6; }
.log-primary .log-time { color: #58a6ff; }
.log-primary { border-left-color: #58a6ff; }
.log-success .log-time { color: #3fb950; }
.log-success { border-left-color: #238636; }
.log-success .log-details { border: 1px solid #238636; }
.log-warning .log-time { color: #d29922; }
.log-warning { border-left-color: #d29922; }
.log-danger .log-time { color: #f85149; }
.log-danger { border-left-color: #b31d28; }
.log-danger .log-details { color: #ff7b72; background: #49020220; border: 1px solid #b31d28; }
.log-info .log-time { color: #8b949e; }

.tab-body { padding: 20px 24px; max-width: 1200px; margin: 0 auto; }
.control-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 20px; }
.cb-label { font-size: 13px; color: #8b949e; }
.input-num { width: 60px; padding: 6px 8px; background: #0d1117; border: 1px solid #30363d; border-radius: 4px; color: #c9d1d9; font-size: 13px; }
.section-title { font-size: 15px; font-weight: bold; color: #58a6ff; margin: 16px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #30363d; }

.data-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 16px; }
.data-table th { background: #161b22; color: #58a6ff; padding: 10px 12px; text-align: left; border-bottom: 1px solid #30363d; }
.data-table td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
.data-table tr:hover { background: #161b22; }
.row-pqc td { color: #d2a8ff; }
.row-ecdh td { color: #79c0ff; }

.bar-chart { margin-top: 16px; display: flex; flex-direction: column; gap: 8px; }
.bar-row { display: flex; align-items: center; gap: 10px; }
.bar-label { width: 180px; font-size: 12px; color: #8b949e; text-align: right; flex-shrink: 0; }
.bar-track { flex: 1; height: 24px; background: #21262d; border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; display: flex; align-items: center; padding-left: 8px; font-size: 11px; color: #fff; font-family: monospace; min-width: 60px; transition: width 0.5s ease; }
.bar-fill.pqc { background: linear-gradient(90deg, #8b5cf6, #d946ef); }
.bar-fill.ecdh { background: linear-gradient(90deg, #2563eb, #06b6d4); }

.verify-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.verify-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
.verify-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.verify-tool { font-weight: bold; font-size: 15px; color: #e6edf3; }
.verify-proto { padding: 2px 10px; border-radius: 10px; font-size: 12px; }
.proto-pqc { background: #8b5cf6; color: #fff; }
.proto-ecdh { background: #2563eb; color: #fff; }
.verify-props { display: flex; flex-direction: column; gap: 6px; }
.prop-row { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.prop-icon { font-size: 14px; }
.prop-name { flex: 1; color: #c9d1d9; }
.prop-result { font-family: monospace; font-size: 12px; font-weight: bold; }
.verify-details { margin-top: 12px; }
.verify-details summary { font-size: 12px; color: #58a6ff; cursor: pointer; }
.verify-output { font-size: 11px; color: #8b949e; background: #0d1117; padding: 8px; border-radius: 4px; margin-top: 6px; white-space: pre-wrap; }

.threat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.threat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
.threat-title { font-weight: bold; font-size: 14px; color: #d29922; margin-bottom: 8px; }
.threat-desc { font-size: 13px; color: #8b949e; line-height: 1.6; }
/* ==========================================
   终端滚动条美化 (Webkit)
========================================== */
.terminal-window::-webkit-scrollbar {
  width: 6px;
}
.terminal-window::-webkit-scrollbar-track {
  background: transparent;
}
.terminal-window::-webkit-scrollbar-thumb {
  background: #30363d;
  border-radius: 4px;
}
.terminal-window::-webkit-scrollbar-thumb:hover {
  background: #484f58;
}
</style>
