#ifndef BIOMODULE_V2_H
#define BIOMODULE_V2_H

#include <vector>
#include <cstdint>
#include <string>

// ============================================================
// BioModuleV2: 增强版模糊提取器
// RS(64,32) t=16 — 专为真实指纹图像的较大帧间变化而设计
// 使用全部 512 维特征（不再做可靠性掩码），bio_key=64字节
// ============================================================
namespace BioModuleV2 {
    using Bytes = std::vector<uint8_t>;

    struct FuzzyExtractorData {
        Bytes P; // 公开辅助数据：64 字节金库
        Bytes R; // 恢复出的主密钥（SHA256，32字节）
    };

    Bytes GenerateMockBiometric(size_t length);

    FuzzyExtractorData Gen(const Bytes& bio);
    Bytes Rep(const Bytes& bio_prime, const Bytes& P);
}

#endif // BIOMODULE_V2_H
