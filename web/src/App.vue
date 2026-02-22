<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import axios from 'axios'
import { ElMessage } from 'element-plus'

// 设备真实状态
const doorStatus = ref(false)
const lightStatus = ref(false)
const acStatus = ref(false)
const acMode = ref<'cool' | 'heat'>('cool')
const acTemp = ref(24)

// 密码学审计日志
interface LogItem { timestamp: string; title: string; content: string; type: 'primary' | 'success' | 'warning' | 'danger' | 'info'; }
const logs = ref<LogItem[]>([])

// 性能统计数据
interface PerfMetrics {
  dhKeyGenTime: number
  ecdhComputeTime: number
  signTime: number
  verifyTime: number
  encryptTime: number
  decryptTime: number
  hkdfTime: number
  dbEncryptTime: number
  dbDecryptTime: number
  registrationTime: number
  challengeGenTime: number
  authVerifyTime: number
  totalAuthTime: number
  totalAuthCount: number
  successAuthCount: number
  failedAuthCount: number
}
const perfMetrics = ref<PerfMetrics>({
  dhKeyGenTime: 0, ecdhComputeTime: 0, signTime: 0, verifyTime: 0,
  encryptTime: 0, decryptTime: 0, hkdfTime: 0, dbEncryptTime: 0, dbDecryptTime: 0,
  registrationTime: 0, challengeGenTime: 0, authVerifyTime: 0, totalAuthTime: 0,
  totalAuthCount: 0, successAuthCount: 0, failedAuthCount: 0
})

const addLog = (title: string, content: string, type: 'primary' | 'success' | 'warning' | 'danger' | 'info' = 'info') => {
  logs.value.unshift({ timestamp: new Date().toLocaleTimeString(), title, content, type })
  if (logs.value.length > 50) logs.value.pop(); // 保留最近50条
}

// 建立大屏专属监听通道
let monitorWs: WebSocket | null = null;

onMounted(() => {
  addLog('系统就绪', '网关监控终端已启动，正在连接服务器...', 'primary')
  monitorWs = new WebSocket('ws://127.0.0.1:8081/ws/monitor') // 注意端口与C++一致

  monitorWs.onmessage = (event) => {
    const data = JSON.parse(event.data)

    if (data.event === 'performance') {
      // 更新性能指标
      perfMetrics.value = data
    } else if (data.event === 'crypto' || data.event === 'system') {
      addLog(data.title, data.details, 'warning')
    } else if (data.event === 'success') {
      addLog(data.title, data.details, 'success')
    } else if (data.event === 'error') {
      addLog(data.title, data.details, 'danger')
    } else if (data.event === 'device_sync') {
      // 收到设备的明文指令，同步右侧动画
      try {
        const cmd = JSON.parse(data.details)
        if (cmd.device === 'door') doorStatus.value = (cmd.action === 'unlock')
        else if (cmd.device === 'light') lightStatus.value = (cmd.action === 'turn_on')
        else if (cmd.device === 'ac') {
          acStatus.value = cmd.power
          acMode.value = cmd.mode
          acTemp.value = cmd.temp
        }
      } catch (e) {
        console.error("同步指令解析失败", e)
      }
    }
  }
})

onUnmounted(() => {
  if (monitorWs) monitorWs.close()
})

// 重置服务器
const resetServer = async () => {
  try {
    // 【关键修复 1】：补全网关的绝对地址，否则会请求到 Vue 自己的端口
    await axios.post('http://127.0.0.1:8081/api/reset')

    doorStatus.value = false; lightStatus.value = false; acStatus.value = false;
    perfMetrics.value = {
      dhKeyGenTime: 0, ecdhComputeTime: 0, signTime: 0, verifyTime: 0,
      encryptTime: 0, decryptTime: 0, hkdfTime: 0, dbEncryptTime: 0, dbDecryptTime: 0,
      registrationTime: 0, challengeGenTime: 0, authVerifyTime: 0, totalAuthTime: 0,
      totalAuthCount: 0, successAuthCount: 0, failedAuthCount: 0
    };
    ElMessage.success('服务器已重置')
  } catch (e) {
    ElMessage.error('重置失败，请检查网关控制台')
  }
}

// 导出性能报告
const exportPerformance = async () => {
  try {
    const response = await axios.get('http://127.0.0.1:8081/api/performance/export')
    ElMessage.success('性能报告已导出到: ' + response.data.file)
  } catch (e) {
    ElMessage.error('导出失败')
  }
}
</script>

<template>
  <div class="dark-dashboard">
    <el-container class="layout-container">
      <el-header class="dashboard-header">
        <div class="logo">🛡️ IoT 密码学安全监控大屏</div>
        <div class="status">
          <el-tag type="success" effect="dark" @click="exportPerformance" style="cursor: pointer; margin-right: 10px;">📊 导出性能报告</el-tag>
          <el-tag type="danger" effect="dark" @click="resetServer" style="cursor: pointer;">🔄 一键清空网关状态</el-tag>
        </div>
      </el-header>

      <el-main>
        <el-row :gutter="20">

          <!-- 性能监控面板 -->
          <el-col :span="24" style="margin-bottom: 20px;">
            <el-card shadow="always" class="panel-card perf-card">
              <template #header><div class="card-header">📊 协议性能实时监控 (Performance Metrics)</div></template>

              <el-row :gutter="15">
                <el-col :span="6">
                  <div class="metric-box">
                    <div class="metric-label">认证总次数</div>
                    <div class="metric-value">{{ perfMetrics.totalAuthCount }}</div>
                  </div>
                </el-col>
                <el-col :span="6">
                  <div class="metric-box success-box">
                    <div class="metric-label">成功认证</div>
                    <div class="metric-value">{{ perfMetrics.successAuthCount }}</div>
                  </div>
                </el-col>
                <el-col :span="6">
                  <div class="metric-box danger-box">
                    <div class="metric-label">失败认证</div>
                    <div class="metric-value">{{ perfMetrics.failedAuthCount }}</div>
                  </div>
                </el-col>
                <el-col :span="6">
                  <div class="metric-box">
                    <div class="metric-label">成功率</div>
                    <div class="metric-value">{{ perfMetrics.totalAuthCount > 0 ? ((perfMetrics.successAuthCount / perfMetrics.totalAuthCount) * 100).toFixed(1) : 0 }}%</div>
                  </div>
                </el-col>
              </el-row>

              <el-divider style="border-color: #30363d; margin: 15px 0;" />

              <el-row :gutter="15">
                <el-col :span="8">
                  <div class="perf-section">
                    <div class="perf-title">🔐 密码学操作耗时 (μs)</div>
                    <div class="perf-item">DH 密钥生成: <span class="perf-num">{{ perfMetrics.dhKeyGenTime.toFixed(2) }}</span></div>
                    <div class="perf-item">ECDH 计算: <span class="perf-num">{{ perfMetrics.ecdhComputeTime.toFixed(2) }}</span></div>
                    <div class="perf-item">ECDSA 签名: <span class="perf-num">{{ perfMetrics.signTime.toFixed(2) }}</span></div>
                    <div class="perf-item">ECDSA 验签: <span class="perf-num">{{ perfMetrics.verifyTime.toFixed(2) }}</span></div>
                    <div class="perf-item">ECIES 加密: <span class="perf-num">{{ perfMetrics.encryptTime.toFixed(2) }}</span></div>
                    <div class="perf-item">ECIES 解密: <span class="perf-num">{{ perfMetrics.decryptTime.toFixed(2) }}</span></div>
                    <div class="perf-item">HKDF 派生: <span class="perf-num">{{ perfMetrics.hkdfTime.toFixed(2) }}</span></div>
                  </div>
                </el-col>
                <el-col :span="8">
                  <div class="perf-section">
                    <div class="perf-title">🗄️ 数据库加密耗时 (μs)</div>
                    <div class="perf-item">字段加密: <span class="perf-num">{{ perfMetrics.dbEncryptTime.toFixed(2) }}</span></div>
                    <div class="perf-item">字段解密: <span class="perf-num">{{ perfMetrics.dbDecryptTime.toFixed(2) }}</span></div>
                  </div>
                </el-col>
                <el-col :span="8">
                  <div class="perf-section">
                    <div class="perf-title">⏱️ 协议阶段耗时 (ms)</div>
                    <div class="perf-item">注册阶段: <span class="perf-num">{{ perfMetrics.registrationTime.toFixed(2) }}</span></div>
                    <div class="perf-item">挑战生成: <span class="perf-num">{{ perfMetrics.challengeGenTime.toFixed(2) }}</span></div>
                    <div class="perf-item">认证验证: <span class="perf-num">{{ perfMetrics.authVerifyTime.toFixed(2) }}</span></div>
                    <div class="perf-item total-time">总认证时间: <span class="perf-num">{{ perfMetrics.totalAuthTime.toFixed(2) }}</span></div>
                  </div>
                </el-col>
              </el-row>
            </el-card>
          </el-col>

          <el-col :span="14">
            <el-card shadow="always" class="panel-card terminal-card">
              <template #header><div class="card-header">💻 底层密码学审计终端 (Live)</div></template>
              
              <div class="terminal-window">
                <transition-group name="list" tag="div">
                  <div v-for="(log, i) in logs" :key="log.timestamp + i" class="log-entry" :class="'log-' + log.type">
                    <div class="log-time">[{{ log.timestamp }}] - {{ log.title }}</div>
                    <pre class="log-details">{{ log.content }}</pre>
                  </div>
                </transition-group>
              </div>
            </el-card>
          </el-col>

          <el-col :span="10">
            <el-card shadow="always" class="panel-card animation-card">
              <template #header><div class="card-header">🏠 终端设备物理映射</div></template>
              
              <div class="animation-container">
                
                <div class="device-card">
                  <div class="door-wrapper" :class="{ 'door-open': doorStatus }">
                    <div class="door"></div>
                  </div>
                  <div class="device-label" :style="{ color: doorStatus ? '#67C23A' : '#F56C6C' }">
                    智能门锁<br/>{{ doorStatus ? '已解锁 🔓' : '已上锁 🔒' }}
                  </div>
                </div>

                <div class="device-card">
                  <div class="light-wrapper" :class="{ 'light-on': lightStatus }">
                    <div class="bulb"></div>
                    <div class="glow" v-if="lightStatus"></div>
                  </div>
                  <div class="device-label" :style="{ color: lightStatus ? '#E6A23C' : '#909399' }">
                    卧室主灯<br/>{{ lightStatus ? '开启 💡' : '关闭 ⚫' }}
                  </div>
                </div>

                <div class="device-card ac-card">
                  <div class="ac-wrapper" :class="{ 'ac-on': acStatus, 'ac-cool': acMode === 'cool', 'ac-heat': acMode === 'heat' }">
                    <div class="ac-body">
                      <div class="ac-logo">IoT-AC</div>
                      <div class="ac-display" v-if="acStatus">{{ acTemp }}°C</div>
                      <div class="ac-flap"></div>
                    </div>
                    <div class="ac-wind" v-if="acStatus">
                      <span class="wind-line"></span><span class="wind-line"></span><span class="wind-line"></span>
                    </div>
                  </div>
                  <div class="device-label" :style="{ color: acStatus ? (acMode==='cool' ? '#58a6ff' : '#f85149') : '#8b949e' }">
                    智能空调<br/>{{ acStatus ? (acMode==='cool' ? '制冷中' : '制热中') + ` ${acTemp}℃` : '待机休眠 💤' }}
                  </div>
                </div>


              </div>
            </el-card>
          </el-col>
        </el-row>
      </el-main>
    </el-container>
  </div>
</template>

<style>
html, body { margin: 0; padding: 0; height: 100%; background-color: #0d1117; }
.dark-dashboard { height: 100vh; color: #E5EAF3; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;}
.dashboard-header { display: flex; justify-content: space-between; align-items: center; background-color: #161b22; border-bottom: 1px solid #30363d; height: 60px; padding: 0 20px; }
.dashboard-header .logo { font-weight: bold; color: #58a6ff; font-size: 18px; }
.panel-card { background-color: #161b22; border: 1px solid #30363d; color: #c9d1d9; height: 85vh; border-radius: 8px;}
.card-header { font-weight: bold; color: #58a6ff; }

/* 炫酷的黑客终端样式 */
.terminal-window { background-color: #010409; height: 100%; overflow-y: auto; padding: 15px; border-radius: 6px; box-shadow: inset 0 0 10px rgba(0,0,0,0.8); }
.log-entry { margin-bottom: 15px; border-left: 3px solid #30363d; padding-left: 10px; }
.log-time { font-size: 13px; font-weight: bold; margin-bottom: 5px; }
.log-details { font-family: 'Fira Code', monospace; font-size: 12px; margin: 0; padding: 8px; background: #0d1117; border-radius: 4px; word-wrap: break-word; white-space: pre-wrap; color: #8b949e; }
.log-primary .log-time { color: #58a6ff; }
.log-success .log-time { color: #3fb950; } .log-success .log-details { border: 1px solid #238636; }
.log-warning .log-time { color: #d29922; }
.log-danger .log-time { color: #f85149; } .log-danger .log-details { color: #ff7b72; background: #49020220; border: 1px solid #b31d28; }

/* 动画过渡 */
.list-enter-active, .list-leave-active { transition: all 0.5s ease; }
.list-enter-from { opacity: 0; transform: translateX(-30px); }
/* ======== 动画沙盘网格布局 ======== */
.animation-container {
  display: grid;
  grid-template-columns: 1fr 1fr; /* 分为两列 */
  gap: 20px; /* 紧凑的模块间距 */
  padding: 10px;
}

/* 独立的设备暗盒 */
.device-card {
  background-color: #0d1117; /* 更深的底色，与外部卡片区分 */
  border: 1px solid #30363d;
  border-radius: 8px;
  padding: 25px 10px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-shadow: inset 0 0 15px rgba(0,0,0,0.6);
}

/* 空调横跨两列 */
.ac-card {
  grid-column: span 2; 
  padding: 30px 10px 20px 10px;
}

.device-label { 
  margin-top: 20px; 
  font-weight: bold; 
  font-size: 14px; 
  text-align: center;
  line-height: 1.6;
  transition: color 0.3s;
}

/* 门锁组件 */
.door-wrapper { width: 80px; height: 120px; background: #21262d; border: 4px solid #30363d; position: relative; perspective: 600px; border-radius: 6px;}
.door { width: 100%; height: 100%; background: linear-gradient(145deg, #5c2e0b, #3b1c04); transform-origin: left; transition: transform 0.6s cubic-bezier(0.4, 0, 0.2, 1); border-right: 2px solid #2a1301;}
.door::after { content: ''; position: absolute; right: 10px; top: 50%; width: 10px; height: 10px; background: #DAA520; border-radius: 50%; box-shadow: 1px 1px 3px rgba(0,0,0,0.5);}
.door-open .door { transform: rotateY(-85deg); }

/* 灯泡组件 */
.light-wrapper { position: relative; width: 60px; height: 90px; display: flex; justify-content: center; align-items: flex-end;}
.bulb { width: 55px; height: 55px; background: #30363d; border-radius: 50%; position: relative; transition: all 0.3s ease; z-index: 2; margin-bottom: 12px;}
.bulb::after { content: ''; position: absolute; bottom: -16px; left: 17px; width: 20px; height: 18px; background: #21262d; border-radius: 0 0 4px 4px; }
.light-on .bulb { background: #E6A23C; box-shadow: 0 0 25px #E6A23C, 0 0 50px #E6A23C; }

/* 空调组件 */
.ac-wrapper { position: relative; width: 200px; height: 80px; margin-bottom: 25px; display: flex; flex-direction: column; align-items: center; }
.ac-body { width: 100%; height: 50px; background: #c9d1d9; border-radius: 6px 6px 4px 4px; position: relative; box-shadow: 0 4px 10px rgba(0,0,0,0.5); z-index: 2; }
.ac-logo { position: absolute; left: 12px; top: 18px; font-size: 11px; color: #8b949e; font-weight: bold;}
.ac-display { position: absolute; right: 12px; top: 12px; background: #010409; padding: 2px 6px; border-radius: 3px; font-size: 14px; font-family: monospace; font-weight: bold; transition: color 0.3s; }
.ac-cool .ac-display { color: #58a6ff; text-shadow: 0 0 4px #58a6ff; }
.ac-heat .ac-display { color: #f85149; text-shadow: 0 0 4px #f85149; }
.ac-flap { position: absolute; bottom: 0; left: 10px; right: 10px; height: 5px; background: #8b949e; border-radius: 2px; transform-origin: top; transition: transform 0.5s; }
.ac-on .ac-flap { transform: rotateX(60deg); }

/* 空调出风动画 */
.ac-wind { position: absolute; top: 50px; display: flex; gap: 25px; opacity: 0; transition: opacity 0.5s; width: 120px; justify-content: center; }
.ac-on .ac-wind { opacity: 0.8; }
.wind-line { display: block; width: 4px; height: 30px; border-radius: 2px; animation: windBlow 1.2s infinite alternate ease-in-out; }
.ac-cool .wind-line { background: linear-gradient(to bottom, rgba(88,166,255,0.8), transparent); }
.ac-heat .wind-line { background: linear-gradient(to bottom, rgba(248,81,73,0.8), transparent); }
.wind-line:nth-child(1) { animation-delay: 0s; }
.wind-line:nth-child(2) { animation-delay: 0.3s; height: 40px; }
.wind-line:nth-child(3) { animation-delay: 0.6s; }

@keyframes windBlow {
  0% { transform: translateY(0) scaleY(1); opacity: 0.2; }
  100% { transform: translateY(25px) scaleY(1.3); opacity: 1; }
}

/* 性能监控面板样式 */
.perf-card { height: auto !important; }
.metric-box { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; text-align: center; }
.metric-box.success-box { border-color: #238636; }
.metric-box.danger-box { border-color: #b31d28; }
.metric-label { font-size: 12px; color: #8b949e; margin-bottom: 8px; }
.metric-value { font-size: 24px; font-weight: bold; color: #58a6ff; font-family: monospace; }
.success-box .metric-value { color: #3fb950; }
.danger-box .metric-value { color: #f85149; }

.perf-section { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }
.perf-title { font-size: 13px; font-weight: bold; color: #58a6ff; margin-bottom: 10px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
.perf-item { font-size: 12px; color: #c9d1d9; margin: 6px 0; display: flex; justify-content: space-between; }
.perf-item.total-time { font-weight: bold; color: #58a6ff; margin-top: 8px; padding-top: 8px; border-top: 1px solid #30363d; }
.perf-num { font-family: 'Fira Code', monospace; color: #3fb950; font-weight: bold; }
</style>