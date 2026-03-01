#include "BioModule.h"
#include "ReedSolomon.h" 
#include <random>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <algorithm>
#include <openssl/sha.h> 

namespace BioModule {

    Bytes GenerateMockBiometric(size_t length) {
        Bytes bio(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(0, 255);
        for (size_t i = 0; i < length; ++i) bio[i] = static_cast<uint8_t>(dis(gen));
        return bio;
    }

    Bytes AddNoise(const Bytes& originalBio, int errorBitsCount) { return originalBio; }

    // =========================================================
    // V4.0 端到端神经密码学：Fuzzy Commitment + 可靠性掩码
    // =========================================================
    // RS(32, 16) 引擎：32字节的纠错码，刚好可以包裹住挑选出的 256-bit 黄金特征
    static RS::ReedSolomonCodec rsEngine(32, 16); 

    // 辅助结构体：用于筛选最强特征
    struct FloatFeature {
        int index;
        float value;
        float abs_val;
    };

    FuzzyExtractorData Gen(const Bytes& bio) {
        FuzzyExtractorData data;
        
        // 验证输入是否为 512 维的 float 数组 (512 * 4 = 2048 bytes)
        if (bio.size() != 512 * sizeof(float)) return data;

        const float* float_data = reinterpret_cast<const float*>(bio.data());
        std::vector<FloatFeature> features(512);
        for (int i = 0; i < 512; ++i) {
            features[i] = {i, float_data[i], std::abs(float_data[i])};
        }

        // 🔥 核心魔法 1：可靠性掩码 (Reliability Masking)
        // 将特征按“绝对值”从大到小排序，把在 0 附近摇摆的垃圾特征全部沉底淘汰！
        std::sort(features.begin(), features.end(), [](const FloatFeature& a, const FloatFeature& b) {
            return a.abs_val > b.abs_val;
        });

        std::vector<uint16_t> reliable_indices(256);
        Bytes bio_key(32, 0); // 32 Bytes = 256 bits

        // 提取最强壮的 Top 256 特征，记录它们的位置，并进行二值化
        for (int i = 0; i < 256; ++i) {
            reliable_indices[i] = features[i].index;
            if (features[i].value > 0) {
                // 将对应 bit 置 1
                bio_key[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        // 生成 16字节(128bit) 高强度主密钥，并通过 RS 扩充为 32字节(256bit) 的容错码字
        Bytes True_K = GenerateMockBiometric(16);
        Bytes Encoded_K = rsEngine.Encode(True_K);

        // 🔥 核心魔法 2：模糊承诺 (Fuzzy Commitment)
        // 直接用生物特征向量与码字进行位异或！一行代码完成绑定！
        Bytes vault_data(32, 0);
        for(int i = 0; i < 32; ++i) {
            vault_data[i] = bio_key[i] ^ Encoded_K[i];
        }

        // 序列化公开辅助数据 P：(256个位置索引 * 2字节) + 32字节金库 = 544 字节
        data.P.clear();
        for(int i = 0; i < 256; ++i) {
            data.P.push_back(reliable_indices[i] >> 8);
            data.P.push_back(reliable_indices[i] & 0xFF);
        }
        data.P.insert(data.P.end(), vault_data.begin(), vault_data.end());

        data.R.resize(SHA256_DIGEST_LENGTH);
        SHA256(True_K.data(), True_K.size(), data.R.data());

        return data;
    }

    Bytes Rep(const Bytes& bio_prime, const Bytes& P) {
        // 校验数据完整性 (544 bytes)
        if (bio_prime.size() != 512 * sizeof(float) || P.size() != 256 * 2 + 32) return Bytes();

        // 1. 从公开数据 P 中读出指路明灯：256个安全索引
        std::vector<uint16_t> reliable_indices(256);
        for (int i = 0; i < 256; ++i) {
            reliable_indices[i] = (P[i * 2] << 8) | P[i * 2 + 1];
        }
        Bytes vault_data(P.begin() + 512, P.end());

        // 2. 解析当前的探针指纹 (它因为环境噪声，在 0 附近发生了大量比特翻转)
        const float* float_data = reinterpret_cast<const float*>(bio_prime.data());

        // 3. 定向狙击：无视其他噪点，只在注册时的 256 个安全位置上提取二值化比特！
        Bytes probe_key(32, 0);
        for (int i = 0; i < 256; ++i) {
            uint16_t idx = reliable_indices[i];
            if (float_data[idx] > 0) {
                probe_key[i / 8] |= (1 << (7 - (i % 8)));
            }
        }

        // 4. 异或解锁：用探针特征剥离金库掩码
        Bytes recovered_Encoded_K(32, 0);
        for(int i = 0; i < 32; ++i) {
            recovered_Encoded_K[i] = probe_key[i] ^ vault_data[i];
        }

        // 5. RS 纠错引擎兜底：吸收掉探针中极个别依然翻转的顽固比特
        bool uncorrectable = false;
        Bytes True_K_recovered = rsEngine.Decode(recovered_Encoded_K, uncorrectable);

        if (uncorrectable || True_K_recovered.empty()) return Bytes();

        Bytes R_recovered(SHA256_DIGEST_LENGTH);
        SHA256(True_K_recovered.data(), True_K_recovered.size(), R_recovered.data());

        return R_recovered;
    }

} // namespace BioModule