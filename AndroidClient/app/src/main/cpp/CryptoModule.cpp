#include "CryptoModule.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h> // 必须包含这个才能使用 d2i_PUBKEY 和 i2d_PUBKEY
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <stdexcept>
#include <cstring> // 用于 std::memcpy
#include <android/log.h>
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "IoT_Auth_Native", __VA_ARGS__)



// 辅助宏：用于 OpenSSL 错误处理
#define HANDLE_SSL_ERROR(condition, msg) \
    if (!(condition)) { throw std::runtime_error(msg); }

namespace CryptoModule {

    using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
    using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

    // ==========================================
    // 基础密码学原语
    // ==========================================

    Bytes Hash(const Bytes& data) {
        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create EVP_MD_CTX");
        Bytes hash(EVP_MAX_MD_SIZE);
        unsigned int length = 0;
        HANDLE_SSL_ERROR(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1, "DigestInit failed");
        HANDLE_SSL_ERROR(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 1, "DigestUpdate failed");
        HANDLE_SSL_ERROR(EVP_DigestFinal_ex(ctx.get(), hash.data(), &length) == 1, "DigestFinal failed");
        hash.resize(length);
        return hash;
    }

    // ==========================================
    // 数字签名方案 (基于 ECDSA, OpenSSL 3.0 规范重写)
    // ==========================================

    KeyPair GenerateSignatureKeyPair(const Bytes& seed) {
        EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
        HANDLE_SSL_ERROR(pctx != nullptr, "Failed to create EVP_PKEY_CTX for parameters");
        HANDLE_SSL_ERROR(EVP_PKEY_paramgen_init(pctx.get()) > 0, "Failed to init paramgen");
        HANDLE_SSL_ERROR(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1) > 0, "Failed to set curve");

        EVP_PKEY* paramsRaw = nullptr;
        HANDLE_SSL_ERROR(EVP_PKEY_paramgen(pctx.get(), &paramsRaw) > 0, "Failed to generate parameters");
        EVP_PKEY_ptr params(paramsRaw, EVP_PKEY_free);

        EVP_PKEY_CTX_ptr kctx(EVP_PKEY_CTX_new(params.get(), nullptr), EVP_PKEY_CTX_free);
        HANDLE_SSL_ERROR(kctx != nullptr, "Failed to create EVP_PKEY_CTX for keygen");
        HANDLE_SSL_ERROR(EVP_PKEY_keygen_init(kctx.get()) > 0, "Failed to init keygen");

        EVP_PKEY* pkeyRaw = nullptr;
        // 如果有 seed (k_master)，理论上需要自定义 BIGNUM 作为私钥 d，但由于 OpenSSL 3.0 EVP 接口的黑盒特性，
        // 确定性生成密钥在纯 EVP 下实现极其繁琐。在原型测试阶段，我们暂时用纯随机代替。
        HANDLE_SSL_ERROR(EVP_PKEY_keygen(kctx.get(), &pkeyRaw) > 0, "Failed to generate EC key pair");
        EVP_PKEY_ptr pkey(pkeyRaw, EVP_PKEY_free);

        KeyPair kp;
        
        // 序列化公钥
        unsigned char* pubKeyBytes = nullptr;
        int pubLen = i2d_PUBKEY(pkey.get(), &pubKeyBytes);
        HANDLE_SSL_ERROR(pubLen > 0, "Failed to serialize public key");
        kp.publicKey.assign(pubKeyBytes, pubKeyBytes + pubLen);
        OPENSSL_free(pubKeyBytes);

        // 序列化私钥
        unsigned char* privKeyBytes = nullptr;
        int privLen = i2d_PrivateKey(pkey.get(), &privKeyBytes);
        HANDLE_SSL_ERROR(privLen > 0, "Failed to serialize private key");
        kp.privateKey.assign(privKeyBytes, privKeyBytes + privLen);
        OPENSSL_free(privKeyBytes);

        return kp;
    }

    Bytes Sign(const Bytes& privateKey, const Bytes& message) {
        // 反序列化私钥
        const unsigned char* privPtr = privateKey.data();
        EVP_PKEY_ptr pkey(d2i_PrivateKey(EVP_PKEY_EC, nullptr, &privPtr, privateKey.size()), EVP_PKEY_free);
        HANDLE_SSL_ERROR(pkey != nullptr, "Failed to deserialize private key for signing");

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create signing context");

        HANDLE_SSL_ERROR(EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) == 1, "DigestSignInit failed");
        HANDLE_SSL_ERROR(EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) == 1, "DigestSignUpdate failed");

        size_t sigLen = 0;
        HANDLE_SSL_ERROR(EVP_DigestSignFinal(ctx.get(), nullptr, &sigLen) == 1, "Failed to get signature length");

        Bytes signature(sigLen);
        HANDLE_SSL_ERROR(EVP_DigestSignFinal(ctx.get(), signature.data(), &sigLen) == 1, "DigestSignFinal failed");
        signature.resize(sigLen);

        return signature;
    }

    bool VerifySignature(const Bytes& publicKey, const Bytes& message, const Bytes& signature) {
        if (publicKey.empty() || message.empty() || signature.empty()) return false;

        // 1. 标准解析公钥
        const unsigned char* pubPtr = publicKey.data();
        EVP_PKEY_ptr pkey(d2i_PUBKEY(nullptr, &pubPtr, publicKey.size()), EVP_PKEY_free);
        if (!pkey) return false;

        // 2. 标准验签流程
        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx) return false;

        if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) != 1) return false;
        if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) != 1) return false;

        return EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) == 1;
    }
    
    // ==========================================
    // DH 前向安全性密钥交换
    // ==========================================
    KeyPair GenerateDHKeyPair() {
        // 1. 创建基于 ECC 的 EVP_PKEY 上下文
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create context for DH keypair generation");

        // 2. 初始化密钥生成器
        HANDLE_SSL_ERROR(EVP_PKEY_keygen_init(ctx.get()) == 1, "Failed to init DH keygen");

        // 3. 设置椭圆曲线参数（这里使用主流且安全的 prime256v1 / P-256）
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>("prime256v1"), 0);
        params[1] = OSSL_PARAM_construct_end();
        HANDLE_SSL_ERROR(EVP_PKEY_CTX_set_params(ctx.get(), params) == 1, "Failed to set curve parameters for DH");

        // 4. 生成密钥对
        EVP_PKEY* pkeyRaw = nullptr;
        HANDLE_SSL_ERROR(EVP_PKEY_keygen(ctx.get(), &pkeyRaw) == 1, "Failed to generate DH keypair");
        EVP_PKEY_ptr pkey(pkeyRaw, EVP_PKEY_free);

        KeyPair kp;

        // 5. 将生成的公钥序列化为网络传输格式 (DER)
        unsigned char* pubKeyBytes = nullptr;
        int pubLen = i2d_PUBKEY(pkey.get(), &pubKeyBytes);
        HANDLE_SSL_ERROR(pubLen > 0, "Failed to serialize DH public key");
        kp.publicKey.assign(pubKeyBytes, pubKeyBytes + pubLen);
        OPENSSL_free(pubKeyBytes); // 必须调用 OPENSSL_free 释放内存

        // 6. 将生成的私钥序列化为存储格式 (DER)
        unsigned char* privKeyBytes = nullptr;
        int privLen = i2d_PrivateKey(pkey.get(), &privKeyBytes);
        HANDLE_SSL_ERROR(privLen > 0, "Failed to serialize DH private key");
        kp.privateKey.assign(privKeyBytes, privKeyBytes + privLen);
        OPENSSL_free(privKeyBytes);

        return kp;
    }

    Bytes ComputeSharedSecret(const Bytes& myPrivateKey, const Bytes& peerPublicKey) {
        const unsigned char* privPtr = myPrivateKey.data();
        EVP_PKEY_ptr myKey(d2i_PrivateKey(EVP_PKEY_EC, nullptr, &privPtr, myPrivateKey.size()), EVP_PKEY_free);
        HANDLE_SSL_ERROR(myKey != nullptr, "Failed to deserialize my private key");

        const unsigned char* pubPtr = peerPublicKey.data();
        EVP_PKEY_ptr peerKey(d2i_PUBKEY(nullptr, &pubPtr, peerPublicKey.size()), EVP_PKEY_free);
        HANDLE_SSL_ERROR(peerKey != nullptr, "Failed to deserialize peer public key");

        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(myKey.get(), nullptr), EVP_PKEY_CTX_free);
        HANDLE_SSL_ERROR(ctx && EVP_PKEY_derive_init(ctx.get()) > 0, "Failed to init DH derive");
        HANDLE_SSL_ERROR(EVP_PKEY_derive_set_peer(ctx.get(), peerKey.get()) > 0, "Failed to set DH peer");

        size_t secretLen = 0;
        HANDLE_SSL_ERROR(EVP_PKEY_derive(ctx.get(), nullptr, &secretLen) > 0, "Failed to determine shared secret length");

        Bytes sharedSecret(secretLen);
        HANDLE_SSL_ERROR(EVP_PKEY_derive(ctx.get(), sharedSecret.data(), &secretLen) > 0, "Failed to derive shared secret");
        sharedSecret.resize(secretLen);

        return sharedSecret;
    }

    KeyPair GenerateEncryptionKeyPair() { return GenerateDHKeyPair(); }

    Bytes Encrypt(const Bytes& publicKey, const Bytes& plaintext) {
        // ECIES 加密方案：临时密钥 + ECDH + AES-256-GCM (256-bit 安全等级)

        // 1. 生成临时 ECDH 密钥对
        KeyPair ephemeralKP = GenerateDHKeyPair();

        // 2. 使用接收方公钥和临时私钥计算共享密钥
        Bytes sharedSecret = ComputeSharedSecret(ephemeralKP.privateKey, publicKey);

        // 3. 从共享密钥派生 AES-256 密钥（使用 PRF 作为 KDF，加入上下文信息）
        Bytes kdfContext = ephemeralKP.publicKey;
        kdfContext.insert(kdfContext.end(), {'E', 'N', 'C'});
        Bytes aesKey = PRF(sharedSecret, kdfContext);

        if (aesKey.size() < 32) {
            throw std::runtime_error("Derived key too short for AES-256");
        }
        aesKey.resize(32); // 使用完整的 256-bit 密钥

        // 4. 生成随机 IV（12 字节用于 GCM 模式）
        Bytes iv(12);
        HANDLE_SSL_ERROR(RAND_bytes(iv.data(), iv.size()) == 1, "Failed to generate IV");

        // 5. 使用 AES-256-GCM 加密明文
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create cipher context");

        // 使用 EVP_aes_256_gcm()
        HANDLE_SSL_ERROR(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, aesKey.data(), iv.data()) == 1,
                        "Failed to init AES-256-GCM encryption");

        Bytes ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
        int len = 0, ciphertext_len = 0;

        HANDLE_SSL_ERROR(EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size()) == 1,
                        "Failed to encrypt data");
        ciphertext_len = len;

        HANDLE_SSL_ERROR(EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) == 1,
                        "Failed to finalize encryption");
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        // 6. 获取 GCM tag（16 字节）
        Bytes tag(16);
        HANDLE_SSL_ERROR(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) == 1,
                        "Failed to get GCM tag");

        // 7. 组装最终密文：临时公钥长度(4字节, 大端序) || 临时公钥 || IV || tag || 密文
        Bytes result;
        uint32_t pubKeyLen = ephemeralKP.publicKey.size();
        
        // 手动将 32 位整数按大端序 (Big-Endian) 拆分为 4 个字节
        uint8_t lenBytes[4] = {
            static_cast<uint8_t>((pubKeyLen >> 24) & 0xFF),
            static_cast<uint8_t>((pubKeyLen >> 16) & 0xFF),
            static_cast<uint8_t>((pubKeyLen >> 8) & 0xFF),
            static_cast<uint8_t>(pubKeyLen & 0xFF)
        };
        result.insert(result.end(), lenBytes, lenBytes + 4);
        result.insert(result.end(), ephemeralKP.publicKey.begin(), ephemeralKP.publicKey.end());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());

        return result;
    }

    Bytes Decrypt(const Bytes& privateKey, const Bytes& ciphertext) {
        // ECIES 解密方案

        if (ciphertext.size() < 4 + 12 + 16) {
            throw std::runtime_error("Ciphertext too short");
        }

        // 1. 提取临时公钥长度 (按大端序反序列化)
        uint32_t pubKeyLen = 0;
        pubKeyLen |= (static_cast<uint32_t>(ciphertext[0]) << 24);
        pubKeyLen |= (static_cast<uint32_t>(ciphertext[1]) << 16);
        pubKeyLen |= (static_cast<uint32_t>(ciphertext[2]) << 8);
        pubKeyLen |= static_cast<uint32_t>(ciphertext[3]);

        if (ciphertext.size() < 4 + pubKeyLen + 12 + 16) {
            throw std::runtime_error("Invalid ciphertext format");
        }

        // 2. 提取各个组件
        size_t offset = 4;
        Bytes ephemeralPubKey(ciphertext.begin() + offset, ciphertext.begin() + offset + pubKeyLen);
        offset += pubKeyLen;

        Bytes iv(ciphertext.begin() + offset, ciphertext.begin() + offset + 12);
        offset += 12;

        Bytes tag(ciphertext.begin() + offset, ciphertext.begin() + offset + 16);
        offset += 16;

        Bytes encryptedData(ciphertext.begin() + offset, ciphertext.end());

        // 3. 使用私钥和临时公钥计算共享密钥
        Bytes sharedSecret = ComputeSharedSecret(privateKey, ephemeralPubKey);

        // 4. 从共享密钥派生 AES-256 密钥
        Bytes kdfContext = ephemeralPubKey;
        kdfContext.insert(kdfContext.end(), {'E', 'N', 'C'});
        Bytes aesKey = PRF(sharedSecret, kdfContext);

        // AES-256 需要 32 字节密钥
        if (aesKey.size() < 32) {
            throw std::runtime_error("Derived key too short for AES-256");
        }
        aesKey.resize(32);

        // 5. 使用 AES-256-GCM 解密
        EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create cipher context");

        // 使用 EVP_aes_256_gcm()
        HANDLE_SSL_ERROR(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, aesKey.data(), iv.data()) == 1,
                        "Failed to init AES-256-GCM decryption");

        Bytes plaintext(encryptedData.size());
        int len = 0, plaintext_len = 0;

        HANDLE_SSL_ERROR(EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, encryptedData.data(), encryptedData.size()) == 1,
                        "Failed to decrypt data");
        plaintext_len = len;

        // 6. 设置 tag 并验证
        HANDLE_SSL_ERROR(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag.data())) == 1,
                        "Failed to set GCM tag");

        HANDLE_SSL_ERROR(EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) == 1,
                        "Failed to finalize decryption or tag verification failed");
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        return plaintext;
    }
    
    // ==========================================
    // HKDF 两阶段密钥派生 (RFC 5869)
    // ==========================================

    Bytes HKDF_Extract(const Bytes& salt, const Bytes& ikm) {
        Bytes effectiveSalt = salt.empty() ? Bytes(32, 0x00) : salt;
        return PRF(effectiveSalt, ikm);
    }

    Bytes HKDF_Expand(const Bytes& prk, const Bytes& info, size_t length) {
        if (length > 255 * 32) {
            throw std::runtime_error("HKDF_Expand: requested length too large");
        }
        Bytes okm;
        Bytes t_prev;
        uint8_t counter = 1;
        while (okm.size() < length) {
            Bytes input = t_prev;
            input.insert(input.end(), info.begin(), info.end());
            input.push_back(counter++);
            t_prev = PRF(prk, input);
            okm.insert(okm.end(), t_prev.begin(), t_prev.end());
        }
        okm.resize(length);
        return okm;
    }

    Bytes PRF(const Bytes& key, const Bytes& data) {
        if (key.empty()) {
            throw std::invalid_argument("PRF key cannot be empty");
        }

        // 1. 使用 OpenSSL 3.0 的 EVP_MAC 接口获取 HMAC 算法
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        HANDLE_SSL_ERROR(mac != nullptr, "Failed to fetch HMAC algorithm");
        std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac_ptr(mac, EVP_MAC_free);

        // 2. 创建 MAC 上下文
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create HMAC context");
        std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx_ptr(ctx, EVP_MAC_CTX_free);

        // 3. 配置底层摘要算法为 SHA256
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
        params[1] = OSSL_PARAM_construct_end();

        // 4. 初始化 PRF，注入密钥 k
        HANDLE_SSL_ERROR(EVP_MAC_init(ctx, key.data(), key.size(), params) == 1, "Failed to init HMAC");
        
        // 5. 注入需要处理的数据 (pw || R)
        if (!data.empty()) {
            HANDLE_SSL_ERROR(EVP_MAC_update(ctx, data.data(), data.size()) == 1, "Failed to update HMAC data");
        }

        // 6. 获取输出长度并提取最终的派生密钥
        size_t outLen = 0;
        HANDLE_SSL_ERROR(EVP_MAC_final(ctx, nullptr, &outLen, 0) == 1, "Failed to get HMAC length");

        Bytes result(outLen);
        HANDLE_SSL_ERROR(EVP_MAC_final(ctx, result.data(), &outLen, result.size()) == 1, "Failed to finalize HMAC");
        result.resize(outLen);

        return result;
    }

} // namespace CryptoModule