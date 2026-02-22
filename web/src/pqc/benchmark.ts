// ==========================================
// ECDH vs ML-KEM-768 性能对比基准测试
// ==========================================
import type { BenchmarkResult } from './types'
import {
  kemKeyGen, kemEncaps, kemDecaps,
  ecdhKeyGen, ecdhDeriveBits,
  KEM_PARAMS
} from './pqc-crypto'

async function measureAsync(fn: () => Promise<void>, runs: number): Promise<{ avg: number; min: number; max: number; std: number }> {
  const times: number[] = []
  // warmup
  for (let i = 0; i < 3; i++) await fn()
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now()
    await fn()
    times.push((performance.now() - t0) * 1000) // 转微秒
  }
  const avg = times.reduce((a, b) => a + b, 0) / times.length
  const min = Math.min(...times)
  const max = Math.max(...times)
  const std = Math.sqrt(times.reduce((s, t) => s + (t - avg) ** 2, 0) / times.length)
  return { avg, min, max, std }
}

export async function runBenchmark(runs: number = 50): Promise<BenchmarkResult[]> {
  const results: BenchmarkResult[] = []

  // ==========================================
  // ML-KEM-768 基准测试
  // ==========================================

  // KEM KeyGen
  let kemKP: Awaited<ReturnType<typeof kemKeyGen>> | null = null
  const kemKG = await measureAsync(async () => { kemKP = await kemKeyGen() }, runs)
  results.push({
    method: 'ML-KEM-768', operation: 'KeyGen',
    avgTime: kemKG.avg, minTime: kemKG.min, maxTime: kemKG.max, stdDev: kemKG.std,
    dataSize: KEM_PARAMS.PK_SIZE + KEM_PARAMS.SK_SIZE, runs
  })

  // KEM Encaps
  const pk = kemKP!.publicKey
  let encResult: Awaited<ReturnType<typeof kemEncaps>> | null = null
  const kemEnc = await measureAsync(async () => { encResult = await kemEncaps(pk) }, runs)
  results.push({
    method: 'ML-KEM-768', operation: 'Encaps',
    avgTime: kemEnc.avg, minTime: kemEnc.min, maxTime: kemEnc.max, stdDev: kemEnc.std,
    dataSize: KEM_PARAMS.CT_SIZE, runs
  })

  // KEM Decaps
  const sk = kemKP!.secretKey
  const ct = encResult!.ciphertext
  const kemDec = await measureAsync(async () => { await kemDecaps(sk, ct) }, runs)
  results.push({
    method: 'ML-KEM-768', operation: 'Decaps',
    avgTime: kemDec.avg, minTime: kemDec.min, maxTime: kemDec.max, stdDev: kemDec.std,
    dataSize: KEM_PARAMS.SS_SIZE, runs
  })

  // ==========================================
  // ECDH P-256 基准测试
  // ==========================================

  // ECDH KeyGen
  let ecdhKP1: Awaited<ReturnType<typeof ecdhKeyGen>> | null = null
  const ecdhKG = await measureAsync(async () => { ecdhKP1 = await ecdhKeyGen() }, runs)
  results.push({
    method: 'ECDH P-256', operation: 'KeyGen',
    avgTime: ecdhKG.avg, minTime: ecdhKG.min, maxTime: ecdhKG.max, stdDev: ecdhKG.std,
    dataSize: 65, runs // P-256 uncompressed public key = 65 bytes
  })

  // ECDH Compute Shared Secret
  const ecdhKP2 = await ecdhKeyGen()
  const ecdhSS = await measureAsync(async () => {
    await ecdhDeriveBits(ecdhKP1!.privateKey, ecdhKP2.publicKey)
  }, runs)
  results.push({
    method: 'ECDH P-256', operation: 'SharedSecret',
    avgTime: ecdhSS.avg, minTime: ecdhSS.min, maxTime: ecdhSS.max, stdDev: ecdhSS.std,
    dataSize: 32, runs
  })

  return results
}

// 导出 CSV 格式
export function benchmarkToCSV(results: BenchmarkResult[]): string {
  let csv = 'Method,Operation,Avg(us),Min(us),Max(us),StdDev(us),DataSize(bytes),Runs\n'
  for (const r of results) {
    csv += `${r.method},${r.operation},${r.avgTime.toFixed(2)},${r.minTime.toFixed(2)},${r.maxTime.toFixed(2)},${r.stdDev.toFixed(2)},${r.dataSize},${r.runs}\n`
  }
  return csv
}

// 数据大小对比
export function getDataSizeComparison() {
  return {
    mlkem: {
      publicKey: KEM_PARAMS.PK_SIZE,
      secretKey: KEM_PARAMS.SK_SIZE,
      ciphertext: KEM_PARAMS.CT_SIZE,
      sharedSecret: KEM_PARAMS.SS_SIZE
    },
    ecdh: {
      publicKey: 65,   // P-256 uncompressed
      privateKey: 32,
      sharedSecret: 32
    }
  }
}
