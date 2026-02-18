#include "BioModuleV2.h"
#include "ReedSolomon.h"
#include <random>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <algorithm>
#include <openssl/sha.h>

namespace BioModuleV2 {

    Bytes GenerateMockBiometric(size_t length) {
        Bytes bio(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; ++i) bio[i] = static_cast<uint8_t>(dis(gen));
        return bio;
    }

    // ============================================================
    // V2 引擎参数：RS(64, 32) → t = 16 字节纠错容量
    //   - 相比 V1 的 RS(32,16) t=8，纠错能力翻倍
    //   - 使用全部 512 维特征（64字节 bio_key），不再丢弃特征
    //   - 设计动机：真实 FVC2002 指纹帧间变化约 15-30 bits，
    //               需要更大的纠错窗口来保证高 TAR
    // ============================================================
    static RS::ReedSolomonCodec rsEngineV2(64, 32); // t = (64-32)/2 = 16

    FuzzyExtractorData Gen(const Bytes& bio) {
        FuzzyExtractorData data;

        // 输入验证：512 维 float32 = 2048 字节
        if (bio.size() != 512 * sizeof(float)) return data;

        const float* float_data = reinterpret_cast<const float*>(bio.data());

        // ── 步骤 1：全特征二值化（512 bits = 64 bytes）──────────────────
        // 不做可靠性掩码，直接对全部 512 个特征取符号位
        Bytes bio_key(64, 0);  // 512 bits → 64 bytes
        for (int i = 0; i < 512; ++i) {
            if (float_data[i] > 0) {
                bio_key[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        // ── 步骤 2：生成 32 字节主密钥，RS(64,32) 编码为 64 字节码字 ──
        Bytes True_K    = GenerateMockBiometric(32);
        Bytes Encoded_K = rsEngineV2.Encode(True_K);   // 64 字节

        // ── 步骤 3：模糊承诺 = bio_key XOR Encoded_K ────────────────────
        Bytes vault_data(64, 0);
        for (int i = 0; i < 64; ++i) {
            vault_data[i] = bio_key[i] ^ Encoded_K[i];
        }

        // ── 步骤 4：序列化公开辅助数据 P = 64 字节金库 ─────────────────
        // V2 不存储位置索引（因为使用全部特征，顺序固定）
        data.P = vault_data;   // 仅 64 字节

        // ── 步骤 5：R = SHA256(True_K) ─────────────────────────────────
        data.R.resize(SHA256_DIGEST_LENGTH);
        SHA256(True_K.data(), True_K.size(), data.R.data());

        return data;
    }

    Bytes Rep(const Bytes& bio_prime, const Bytes& P) {
        // 校验：2048 字节特征 + 64 字节 P
        if (bio_prime.size() != 512 * sizeof(float) || P.size() != 64) return Bytes();

        const float* float_data = reinterpret_cast<const float*>(bio_prime.data());

        // ── 步骤 1：全特征二值化（与 Gen 相同顺序）────────────────────
        Bytes probe_key(64, 0);
        for (int i = 0; i < 512; ++i) {
            if (float_data[i] > 0) {
                probe_key[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        // ── 步骤 2：XOR 解锁：probe_key XOR vault → 含噪码字 ──────────
        Bytes recovered_Encoded_K(64, 0);
        for (int i = 0; i < 64; ++i) {
            recovered_Encoded_K[i] = probe_key[i] ^ P[i];
        }

        // ── 步骤 3：RS(64,32) 纠错，恢复 True_K ────────────────────────
        bool uncorrectable = false;
        Bytes True_K_recovered = rsEngineV2.Decode(recovered_Encoded_K, uncorrectable);

        if (uncorrectable || True_K_recovered.empty()) return Bytes();

        // ── 步骤 4：R = SHA256(True_K) ─────────────────────────────────
        Bytes R_recovered(SHA256_DIGEST_LENGTH);
        SHA256(True_K_recovered.data(), True_K_recovered.size(), R_recovered.data());

        return R_recovered;
    }

} // namespace BioModuleV2
