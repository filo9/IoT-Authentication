#pragma once

#include <string>
#include <vector>
#include "CryptoModule.h"
#include "SecureBytes.h"

// ============================================================
// TEEKeyModule — 设备绑定硬件密钥模块
//
// 替代原 PUF + SecureCredentialManager 方案，对应协议中的 K。
//
// 架构（方案一 + 方案四结合）：
//   Android 端：通过 Android Keystore（TEE/StrongBox）生成
//               不可导出的 ECDH 密钥对；K 由设备内 ECDH 运算
//               在 TEE 内派生，原始值永不离开安全区。
//
//   服务端/网关端（C++ 原型）：使用 PBKDF2(deviceUID, salt, N)
//               模拟 TPM NV 存储的确定性设备密钥，无 PUF 随机
//               噪声依赖，可直接替换原 SecureCredentialManager。
//
// 接口约定：
//   Enroll()   —— 首次注册时生成并持久化设备密钥材料
//   Derive()   —— 认证时确定性地重新派生相同的 K
//   ComputeMasterKey() —— kmaster = PRF(K, pw || R)，绑定三因素
// ============================================================

namespace TEEKeyModule {

// -------------------------------------------------------
// 设备密钥派生参数（服务端 C++ 原型）
// -------------------------------------------------------
constexpr int PBKDF2_ITERATIONS = 200000;  // 高迭代次数抵抗暴力破解
constexpr int KEY_BYTES         = 32;      // 256-bit 设备密钥

// -------------------------------------------------------
// Enroll: 注册阶段
//   - 生成随机 salt 并与 deviceUID 共同经 PBKDF2 派生 K
//   - 将 salt 持久化到 keystoreFile（明文存储；K 本身不落盘）
//   - 返回派生的设备密钥 K（调用方负责安全擦除）
// -------------------------------------------------------
SecureBytes Enroll(const std::string& deviceUID,
                   const std::string& keystoreFile);

// -------------------------------------------------------
// Derive: 认证阶段
//   - 从 keystoreFile 读取 salt
//   - 与 deviceUID 共同经 PBKDF2 重新派生 K
//   - 返回与 Enroll 完全相同的 K（确定性）
// -------------------------------------------------------
SecureBytes Derive(const std::string& deviceUID,
                   const std::string& keystoreFile);

// -------------------------------------------------------
// ComputeMasterKey: 三因素绑定主密钥派生
//   kmaster = HMAC-SHA256(K, pw || R)
//   其中：K = 设备因素, pw = 知识因素, R = 生物因素
// -------------------------------------------------------
SecureBytes ComputeMasterKey(const SecureBytes&           deviceKey,
                             const CryptoModule::Bytes&   password,
                             const CryptoModule::Bytes&   bioSecret);

} // namespace TEEKeyModule
