#include "PUFModule.h"
#include "ReedSolomon.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <random>
#include <cstring>
#include <stdexcept>

namespace PUFModule {

    // SRAM PUF 模拟器：基于设备 challenge 生成伪随机但确定性的"硬件响应"
    // 真实 PUF 会读取芯片物理特性（如 SRAM 上电状态、晶体管延迟差异）
    static CryptoModule::Bytes SimulateSRAM_PUF(const std::string& challenge) {
        // 使用 challenge 作为种子，生成确定性的"硬件指纹"
        std::seed_seq seed(challenge.begin(), challenge.end());
        std::mt19937_64 rng(seed);

        // 生成 512 字节的 PUF 响应（模拟 SRAM 单元的 0/1 状态）
        CryptoModule::Bytes response(512);
        for (size_t i = 0; i < response.size(); ++i) {
            response[i] = static_cast<uint8_t>(rng() & 0xFF);
        }

        return response;
    }

    // 添加噪声：模拟 PUF 响应的不稳定性（温度、电压波动导致的比特翻转）
    static CryptoModule::Bytes AddPUFNoise(const CryptoModule::Bytes& original, double errorRate = 0.05) {
        CryptoModule::Bytes noisy = original;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);

        // 以 errorRate 概率翻转每个比特
        for (size_t i = 0; i < noisy.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                if (dis(gen) < errorRate) {
                    noisy[i] ^= (1 << bit);
                }
            }
        }

        return noisy;
    }

    // ==========================================
    // 注册阶段：生成 PUF 响应和辅助数据
    // ==========================================
    PUFResponse Enroll(const std::string& challenge) {
        PUFResponse pufResp;

        // 1. 读取硬件 PUF 响应（模拟）
        CryptoModule::Bytes rawResponse = SimulateSRAM_PUF(challenge);

        // 2. 使用 Reed-Solomon 生成辅助数据（用于后续纠错）
        // RS(64, 32) t=16：可纠正 16 字节错误
        static RS::ReedSolomonCodec rsCodec(64, 32);

        // 从 512 字节 PUF 响应中提取前 32 字节作为密钥材料
        CryptoModule::Bytes keyMaterial(rawResponse.begin(), rawResponse.begin() + 32);

        // RS 编码
        CryptoModule::Bytes encoded = rsCodec.Encode(keyMaterial);

        // 生成辅助数据：helper = rawResponse XOR encoded（扩展到 512 字节）
        pufResp.helper.resize(512, 0x00);
        for (size_t i = 0; i < 64 && i < rawResponse.size(); ++i) {
            pufResp.helper[i] = rawResponse[i] ^ encoded[i];
        }

        pufResp.response = rawResponse;
        return pufResp;
    }

    // ==========================================
    // 认证阶段：重构 PUF 响应
    // ==========================================
    CryptoModule::Bytes Reconstruct(const std::string& challenge, const CryptoModule::Bytes& helper) {
        if (helper.size() < 64) {
            throw std::runtime_error("PUF helper data too short");
        }

        // 1. 重新读取硬件 PUF 响应（带噪声）
        CryptoModule::Bytes rawResponse = SimulateSRAM_PUF(challenge);
        CryptoModule::Bytes noisyResponse = AddPUFNoise(rawResponse, 0.05);

        // 2. 使用辅助数据恢复编码后的密钥材料
        CryptoModule::Bytes noisyEncoded(64);
        for (size_t i = 0; i < 64; ++i) {
            noisyEncoded[i] = noisyResponse[i] ^ helper[i];
        }

        // 3. RS 解码纠错
        static RS::ReedSolomonCodec rsCodec(64, 32);
        bool uncorrectable = false;
        CryptoModule::Bytes recovered = rsCodec.Decode(noisyEncoded, uncorrectable);

        if (uncorrectable || recovered.empty()) {
            throw std::runtime_error("PUF reconstruction failed: too many errors");
        }

        // 4. 扩展回 512 字节（用于后续密钥派生）
        CryptoModule::Bytes fullResponse(512);
        std::memcpy(fullResponse.data(), recovered.data(), std::min(recovered.size(), fullResponse.size()));

        return fullResponse;
    }

    // ==========================================
    // 从 PUF 响应派生设备密钥 k
    // ==========================================
    CryptoModule::Bytes DeriveKeyFromPUF(const CryptoModule::Bytes& pufResponse) {
        // 使用 SHA-256 将 PUF 响应压缩为 32 字节密钥
        CryptoModule::Bytes key(SHA256_DIGEST_LENGTH);
        SHA256(pufResponse.data(), pufResponse.size(), key.data());
        return key;
    }

} // namespace PUFModule
