# 性能监控与基准测试

## 概述

本项目集成了全方位的性能监控系统，用于测量和分析 IoT 认证协议各阶段的执行效率，为论文提供详实的性能数据支撑。

## 监控架构

### 1. 网关端（C++ Server）

**监控指标：**

- **密码学操作耗时（微秒级）**
  - DH 密钥生成 (dhKeyGenTime)
  - ECDH 共享秘密计算 (ecdhComputeTime)
  - ECDSA 签名 (signTime)
  - ECDSA 验签 (verifyTime)
  - ECIES 加密 (encryptTime)
  - ECIES 解密 (decryptTime)
  - HKDF 密钥派生 (hkdfTime)
  - 数据库字段加密 (dbEncryptTime)
  - 数据库字段解密 (dbDecryptTime)

- **协议阶段耗时（毫秒级）**
  - 注册阶段总耗时 (registrationTime)
  - 挑战生成耗时 (challengeGenTime)
  - 认证验证耗时 (authVerifyTime)
  - 总认证时间 (totalAuthTime)

- **统计计数器**
  - 总认证次数 (totalAuthCount)
  - 成功认证次数 (successAuthCount)
  - 失败认证次数 (failedAuthCount)
  - 成功率 (%)

**实现位置：**
- `include/Server.h` - PerformanceMetrics 结构体定义
- `src/Server.cpp` - 各函数中使用 std::chrono::high_resolution_clock 计时
- `src/main_server.cpp` - 每 2 秒通过 WebSocket 广播性能数据

### 2. Android 客户端（Kotlin）

**监控指标：**

- 注册总耗时（从点击按钮到完成）
- TEE 指纹验证耗时
- 载荷生成耗时
- 认证总耗时（从发起到完成）
- 网络延迟（挑战包往返时间）
- 响应生成耗时
- 最终验证耗时

**实现位置：**
- `MainActivity.kt` - 使用 System.currentTimeMillis() 记录各阶段时间戳
- 性能数据直接显示在 TextView 中

### 3. Web 监控大屏（Vue.js）

**功能：**

- 实时显示网关性能指标（每 2 秒更新）
- 可视化展示：
  - 认证统计卡片（总次数、成功、失败、成功率）
  - 密码学操作耗时表格
  - 数据库加密耗时表格
  - 协议阶段耗时表格
- 一键导出性能报告到 CSV

**实现位置：**
- `web/src/App.vue` - 性能监控面板 UI 和数据接收逻辑

## 使用方法

### 启动监控系统

1. **启动网关服务器：**
```bash
cd build
./iot_gateway_server
```

2. **启动 Web 监控大屏：**
```bash
cd web
npm run dev
```
访问 http://localhost:5173 查看实时性能数据

3. **运行 Android 客户端：**
- 在 Android Studio 中运行应用
- 执行注册和认证操作
- 查看 TextView 中的性能统计

### 导出性能报告

**方法 1：通过 Web 界面**
- 点击右上角 "📊 导出性能报告" 按钮
- 报告自动保存到网关运行目录的 `performance_report.csv`

**方法 2：通过 API**
```bash
curl http://127.0.0.1:8081/api/performance/export
```

**方法 3：程序化调用**
```cpp
gateway.ExportPerformanceReport("custom_path.csv");
```

## 性能报告格式

CSV 文件包含以下字段：

```csv
Metric,Value,Unit
DH Key Generation,1234.56,us
ECDH Compute,987.65,us
ECDSA Sign,543.21,us
ECDSA Verify,456.78,us
ECIES Encrypt,2345.67,us
ECIES Decrypt,2123.45,us
HKDF Derivation,234.56,us
DB Field Encrypt,345.67,us
DB Field Decrypt,321.09,us
Registration Phase,12.34,ms
Challenge Generation,5.67,ms
Auth Verification,23.45,ms
Total Auth Time,29.12,ms
Total Auth Attempts,100,count
Successful Auths,95,count
Failed Auths,5,count
Success Rate,95.0,%
```

## 论文数据采集建议

### 实验设置

1. **单次认证性能测试：**
   - 运行 10 次成功认证
   - 记录每次的 totalAuthTime
   - 计算平均值、标准差、最小值、最大值

2. **密码学原语性能对比：**
   - 对比 ECDH vs RSA 密钥交换
   - 对比 ECDSA vs RSA 签名
   - 对比 ECIES vs RSA-OAEP 加密

3. **并发性能测试：**
   - 模拟多个设备同时认证
   - 测量 TPS (Transactions Per Second)
   - 观察性能瓶颈

### 绘图数据提取

使用 Python 脚本处理 CSV：

```python
import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv('performance_report.csv')

# 提取密码学操作耗时
crypto_ops = df[df['Unit'] == 'us'].head(9)
plt.barh(crypto_ops['Metric'], crypto_ops['Value'])
plt.xlabel('Time (μs)')
plt.title('Cryptographic Operations Performance')
plt.tight_layout()
plt.savefig('crypto_performance.png', dpi=300)
```

## 性能优化建议

根据监控数据，可以针对性优化：

1. **如果 ECIES 加密/解密耗时过高：**
   - 考虑使用 ECDH + AES-GCM 替代 ECIES
   - 或使用硬件加速（AES-NI）

2. **如果 HKDF 耗时过高：**
   - 检查是否多次调用，考虑缓存 PRK

3. **如果数据库加密耗时过高：**
   - 考虑使用数据库原生加密功能
   - 或仅加密敏感字段

4. **如果总认证时间过长：**
   - 分析各阶段占比
   - 优化网络延迟（使用 HTTP/2 或 QUIC）
   - 优化生物特征处理（使用 GPU 加速）

## 注意事项

- 性能数据仅在内存中维护，重启网关后清零
- 每次认证会更新最新的操作耗时（覆盖上一次）
- 统计计数器会累加
- Web 大屏每 2 秒刷新一次数据
- 导出的 CSV 文件包含当前时刻的快照数据
