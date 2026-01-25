#ifndef BIOMODULE_H
#define BIOMODULE_H

#include <vector>
#include <cstdint>
#include <string>

namespace BioModule {
    using Bytes = std::vector<uint8_t>;

    struct FuzzyExtractorData {
        Bytes P; // 公开的模糊金库数据 (Vault)
        Bytes R; // 恢复出的主密钥 (256-bit SHA256)
    };

    // 辅助工具
    Bytes GenerateMockBiometric(size_t length);
    Bytes AddNoise(const Bytes& originalBio, int errorBitsCount);

    // =========================================================
    // 核心接口：基于 GF(2^16) 的指纹模糊金库 (Fuzzy Vault)
    // =========================================================
    // 核心接口：模糊提取器（RS字节级纠错 + Hamming比特级二次校验）
    FuzzyExtractorData Gen(const Bytes& bio);
    Bytes Rep(const Bytes& bio_prime, const Bytes& P);
}

#endif // BIOMODULE_H