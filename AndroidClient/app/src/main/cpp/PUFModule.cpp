#include "PUFModule.h"
#include "ReedSolomon.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <random>
#include <cstring>
#include <stdexcept>

namespace PUFModule {

    static CryptoModule::Bytes SimulateSRAM_PUF(const std::string& challenge) {
        std::seed_seq seed(challenge.begin(), challenge.end());
        std::mt19937_64 rng(seed);
        CryptoModule::Bytes response(512);
        for (size_t i = 0; i < response.size(); ++i) {
            response[i] = static_cast<uint8_t>(rng() & 0xFF);
        }
        return response;
    }

    static CryptoModule::Bytes AddPUFNoise(const CryptoModule::Bytes& original, double errorRate = 0.05) {
        CryptoModule::Bytes noisy = original;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0.0, 1.0);
        for (size_t i = 0; i < noisy.size(); ++i) {
            for (int bit = 0; bit < 8; ++bit) {
                if (dis(gen) < errorRate) {
                    noisy[i] ^= (1 << bit);
                }
            }
        }
        return noisy;
    }

    PUFResponse Enroll(const std::string& challenge) {
        PUFResponse pufResp;
        CryptoModule::Bytes rawResponse = SimulateSRAM_PUF(challenge);
        static RS::ReedSolomonCodec rsCodec(64, 32);

        // 只取前 32 字节作为受保护的真实密钥材料
        CryptoModule::Bytes keyMaterial(rawResponse.begin(), rawResponse.begin() + 32);
        CryptoModule::Bytes encoded = rsCodec.Encode(keyMaterial);

        pufResp.helper.resize(512, 0x00);
        for (size_t i = 0; i < 64 && i < rawResponse.size(); ++i) {
            pufResp.helper[i] = rawResponse[i] ^ encoded[i];
        }

        // 【核心修复】：直接将 32 字节的 keyMaterial 作为最终的 PUF 响应返回
        pufResp.response = keyMaterial;
        return pufResp;
    }

    CryptoModule::Bytes Reconstruct(const std::string& challenge, const CryptoModule::Bytes& helper) {
        if (helper.size() < 64) throw std::runtime_error("PUF helper data too short");
        CryptoModule::Bytes rawResponse = SimulateSRAM_PUF(challenge);

        // 噪声率控制在 1% (约 5 个比特翻转)，确保在 RS(64,32) 的 16 字节纠错能力内
        CryptoModule::Bytes noisyResponse = AddPUFNoise(rawResponse, 0.01);

        CryptoModule::Bytes noisyEncoded(64);
        for (size_t i = 0; i < 64; ++i) {
            noisyEncoded[i] = noisyResponse[i] ^ helper[i];
        }

        static RS::ReedSolomonCodec rsCodec(64, 32);
        bool uncorrectable = false;
        CryptoModule::Bytes recovered = rsCodec.Decode(noisyEncoded, uncorrectable);

        if (uncorrectable || recovered.empty()) {
            throw std::runtime_error("PUF reconstruction failed");
        }

        // 【核心修复】：直接返回 32 字节恢复成功的密钥，不要再去补 480 字节的 0 了！
        return recovered;
    }

    CryptoModule::Bytes DeriveKeyFromPUF(const CryptoModule::Bytes& pufResponse) {
        CryptoModule::Bytes key(SHA256_DIGEST_LENGTH);
        SHA256(pufResponse.data(), pufResponse.size(), key.data());
        return key;
    }

} // namespace PUFModule
