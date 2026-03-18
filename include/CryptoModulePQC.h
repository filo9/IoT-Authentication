#pragma once

#include "CryptoModule.h"
#include <vector>
#include <cstdint>

// ==========================================
// 后量子密码学模块 (Post-Quantum Cryptography)
// ML-KEM-768 密钥封装机制 (NIST FIPS 203)
// ==========================================
// 由于 OpenSSL 3.3 不支持 ML-KEM，此处使用纯 C++ 软件模拟
// 安全性等价于 AES-192，密钥尺寸：pk=1184, sk=2400, ct=1088, ss=32

namespace CryptoModulePQC {

    using Bytes = CryptoModule::Bytes;

    // ML-KEM-768 参数常量
    constexpr size_t MLKEM768_PK_SIZE  = 1184;  // 公钥大小
    constexpr size_t MLKEM768_SK_SIZE  = 2400;  // 私钥大小
    constexpr size_t MLKEM768_CT_SIZE  = 1088;  // 密文大小
    constexpr size_t MLKEM768_SS_SIZE  = 32;    // 共享密钥大小

    // KEM 密钥对
    struct KEMKeyPair {
        Bytes publicKey;   // 1184 bytes
        Bytes secretKey;   // 2400 bytes
    };

    // KEM 封装结果
    struct KEMEncapsResult {
        Bytes ciphertext;     // 1088 bytes
        Bytes sharedSecret;   // 32 bytes
    };

    // ==========================================
    // ML-KEM-768 核心接口
    // ==========================================

    // 密钥生成: (pk, sk) <- ML-KEM.KeyGen()
    KEMKeyPair KEM_KeyGen();

    // 封装 (客户端调用): (ct, ss) <- ML-KEM.Encaps(pk)
    KEMEncapsResult KEM_Encaps(const Bytes& publicKey);

    // 解封装 (服务器调用): ss <- ML-KEM.Decaps(sk, ct)
    Bytes KEM_Decaps(const Bytes& secretKey, const Bytes& ciphertext);

    // ==========================================
    // 复用原有密码学原语 (直接委托给 CryptoModule)
    // ==========================================

    inline Bytes Hash(const Bytes& data) { return CryptoModule::Hash(data); }
    inline Bytes PRF(const Bytes& key, const Bytes& data) { return CryptoModule::PRF(key, data); }
    inline CryptoModule::KeyPair GenerateSignatureKeyPair(const Bytes& seed = {}) {
        return CryptoModule::GenerateSignatureKeyPair(seed);
    }
    inline Bytes Sign(const Bytes& privateKey, const Bytes& message) {
        return CryptoModule::Sign(privateKey, message);
    }
    inline bool VerifySignature(const Bytes& publicKey, const Bytes& message, const Bytes& signature) {
        return CryptoModule::VerifySignature(publicKey, message, signature);
    }
    inline CryptoModule::KeyPair GenerateEncryptionKeyPair() {
        return CryptoModule::GenerateEncryptionKeyPair();
    }
    inline Bytes Encrypt(const Bytes& publicKey, const Bytes& plaintext) {
        return CryptoModule::Encrypt(publicKey, plaintext);
    }
    inline Bytes Decrypt(const Bytes& privateKey, const Bytes& ciphertext) {
        return CryptoModule::Decrypt(privateKey, ciphertext);
    }
    inline Bytes HKDF_Extract(const Bytes& salt, const Bytes& ikm) {
        return CryptoModule::HKDF_Extract(salt, ikm);
    }
    inline Bytes HKDF_Expand(const Bytes& prk, const Bytes& info, size_t length) {
        return CryptoModule::HKDF_Expand(prk, info, length);
    }

} // namespace CryptoModulePQC
