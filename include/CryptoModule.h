#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace CryptoModule {

    // 使用 std::vector<uint8_t> 作为通用字节数组载体
    using Bytes = std::vector<uint8_t>;

    // 统一的非对称密钥对结构
    struct KeyPair {
        Bytes publicKey;
        Bytes privateKey;
    };

    // ==========================================
    // 基础密码学原语
    // ==========================================
    
    // 安全哈希函数 H(·)，协议中多处用于生成 tag 和派生密钥 [cite: 140, 187, 198]
    Bytes Hash(const Bytes& data);
    
    // 伪随机函数 F(k, pw || R)，用于融合多因子生成主密钥 kmaster [cite: 157, 183]
    Bytes PRF(const Bytes& key, const Bytes& data);

    // ==========================================
    // 数字签名方案 (Pi_Sign) 
    // ==========================================
    
    // 生成签名密钥对 (对应 KGen_S 或 Sig.KeyGen) [cite: 146, 158]
    // 如果传入 seed (如 kmaster)，则进行确定性推导；否则随机生成
    KeyPair GenerateSignatureKeyPair(const Bytes& seed = {});
    
    // 签名算法 Sign(sk, message) [cite: 188]
    Bytes Sign(const Bytes& privateKey, const Bytes& message);
    
    // 验证算法 Vf(pk, message, sigma) [cite: 195]
    bool VerifySignature(const Bytes& publicKey, const Bytes& message, const Bytes& signature);

    // ==========================================
    // 公钥加密方案 (Pi_Enc)
    // ==========================================
    
    // 生成加密密钥对 KGen_E [cite: 159]
    KeyPair GenerateEncryptionKeyPair();
    
    // 加密算法 Enc(pk, plaintext) [cite: 189]
    Bytes Encrypt(const Bytes& publicKey, const Bytes& plaintext);
    
    // 解密算法 Dec(sk, ciphertext) [cite: 194]
    Bytes Decrypt(const Bytes& privateKey, const Bytes& ciphertext);

    // ==========================================
    // HKDF 两阶段密钥派生 (RFC 5869)
    // ==========================================

    // Extract 阶段: PRK = HKDF-Extract(salt, IKM)
    // salt: 通常为 dhpubS || dhpubU，IKM: ECDH 原始共享秘密
    Bytes HKDF_Extract(const Bytes& salt, const Bytes& ikm);

    // Expand 阶段: OKM = HKDF-Expand(PRK, info, length)
    // 从同一 PRK 派生多个独立子密钥
    Bytes HKDF_Expand(const Bytes& prk, const Bytes& info, size_t length);

    // ==========================================
    // Diffie-Hellman 密钥交换 (ECDH)
    // ==========================================
    
    // 生成临时 DH 密钥对 dh_priv, dh_pub <- DH.KeyGen() [cite: 176, 185]
    KeyPair GenerateDHKeyPair();
    
    // 计算共享秘密 sharedsecret <- DH.Agreement(dh_pub, dh_priv) [cite: 186, 196]
    Bytes ComputeSharedSecret(const Bytes& myPrivateKey, const Bytes& peerPublicKey);

} // namespace CryptoModule