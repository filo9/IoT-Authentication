#ifndef PUF_MODULE_H
#define PUF_MODULE_H

#include "CryptoModule.h"
#include <string>
#include <vector>

// ==========================================
// PUF (Physical Unclonable Function) 模块
// ==========================================
// 模拟硬件物理不可克隆函数，用于生成设备唯一的硬件指纹
// 真实实现可基于 SRAM PUF、Ring Oscillator PUF 或 Arbiter PUF
namespace PUFModule {

    // PUF 响应数据（带噪声，需要模糊提取器稳定化）
    struct PUFResponse {
        CryptoModule::Bytes response;  // PUF 原始响应（512 字节）
        CryptoModule::Bytes helper;    // 辅助数据（用于纠错）
    };

    // ==========================================
    // 注册阶段：生成 PUF 响应和辅助数据
    // ==========================================
    // challenge: 输入激励（如设备 UID）
    // 返回: PUF 响应 + 辅助数据（用于后续稳定化）
    PUFResponse Enroll(const std::string& challenge);

    // ==========================================
    // 认证阶段：重构 PUF 响应
    // ==========================================
    // challenge: 相同的输入激励
    // helper: 注册时生成的辅助数据
    // 返回: 稳定化后的 PUF 响应（与注册时一致）
    CryptoModule::Bytes Reconstruct(const std::string& challenge, const CryptoModule::Bytes& helper);

    // ==========================================
    // 从 PUF 响应派生设备密钥 k
    // ==========================================
    // 使用 SHA-256 将 PUF 响应压缩为 32 字节密钥
    CryptoModule::Bytes DeriveKeyFromPUF(const CryptoModule::Bytes& pufResponse);

} // namespace PUFModule

#endif // PUF_MODULE_H
