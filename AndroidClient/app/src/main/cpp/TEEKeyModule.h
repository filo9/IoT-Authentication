#pragma once

#include <string>
#include <vector>
#include "CryptoModule.h"
#include "SecureBytes.h"

// ============================================================
// TEEKeyModule — Android 端设备绑定硬件密钥模块
//
// 替代原 PUF + SecureCredentialManager 方案。
//
// Android 实现策略（方案一 + 方案四结合）：
//
//   【方案一】Android Keystore HMAC：
//     在 Keystore 中生成硬件支持的 HmacSHA256 密钥（不可导出）。
//     K = Keystore.HMAC(hw_key, "tee_device_key_v1" || deviceUID)
//     密钥操作在 TEE/StrongBox 内完成，K 本身不离开安全区。
//
//   【方案四】降级路径（Keystore 不可用时）：
//     K = PBKDF2(deviceUID, stored_salt, N=200000)
//     保证在无 TEE 的模拟器/低端设备上仍可运行。
//
// 注意：Android Keystore 的实际调用通过 JNI 回调到 Kotlin 层完成
//       （Kotlin 持有 KeyStore 实例，C++ 通过 native_tee_hmac() 请求）。
//       本头文件声明 C++ 侧接口；JNI 桥接在 native-lib.cpp 实现。
// ============================================================

namespace TEEKeyModule {

constexpr int PBKDF2_ITERATIONS = 200000;
constexpr int KEY_BYTES         = 32;

// -------------------------------------------------------
// Enroll: 注册阶段
//   优先使用 Android Keystore HMAC；
//   不可用时生成 salt 并走 PBKDF2 降级路径。
//   keystoreFile 用于存储降级路径所需的 salt。
// -------------------------------------------------------
SecureBytes Enroll(const std::string& deviceUID,
                   const std::string& keystoreFile);

// -------------------------------------------------------
// Derive: 认证阶段（确定性重新派生相同的 K）
// -------------------------------------------------------
SecureBytes Derive(const std::string& deviceUID,
                   const std::string& keystoreFile);

// -------------------------------------------------------
// ComputeMasterKey: kmaster = HMAC-SHA256(K, pw || R)
// -------------------------------------------------------
SecureBytes ComputeMasterKey(const SecureBytes&           deviceKey,
                             const CryptoModule::Bytes&   password,
                             const CryptoModule::Bytes&   bioSecret);

// -------------------------------------------------------
// JNI 回调：由 native-lib.cpp 注册，供 Enroll/Derive 调用
// 若未注册（非 Android 环境），则走 PBKDF2 降级路径。
// -------------------------------------------------------
using KeystoreHmacFn = std::vector<uint8_t>(*)(const std::string& keyAlias,
                                               const std::vector<uint8_t>& data);
void RegisterKeystoreHmacCallback(KeystoreHmacFn fn);

} // namespace TEEKeyModule
