#include "DeterministicECC.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/obj_mac.h> // 必须引入此头文件以获取 NID_X9_62_prime256v1
#include <stdexcept>
#include <vector>

// 局部错误拦截宏
#ifndef HANDLE_SSL_ERROR
#define HANDLE_SSL_ERROR(condition, msg) \
    if (!(condition)) { throw std::runtime_error(msg); }
#endif

namespace DeterministicECC {

    // 智能指针类型定义
    using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
    using EC_GROUP_ptr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
    using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

    CryptoModule::KeyPair DeriveKeyPairFromSeed(const CryptoModule::Bytes& seed) {
        if (seed.empty()) {
            throw std::invalid_argument("Seed cannot be empty for deterministic derivation.");
        }

        CryptoModule::KeyPair kp;

        // 1. 将高熵种子转化为 P-256 曲线适配的 256-bit 大整数 (即私钥 d)
        CryptoModule::Bytes privBytes = CryptoModule::Hash(seed); 
        BIGNUM_ptr privBN(BN_bin2bn(privBytes.data(), privBytes.size(), nullptr), BN_clear_free);
        HANDLE_SSL_ERROR(privBN != nullptr, "Failed to create BIGNUM from seed");

        // =====================================================================
        // 2. 学术高光时刻：手动执行椭圆曲线标量乘法计算公钥 (Q = d * G)
        // =====================================================================
        EC_GROUP_ptr group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
        HANDLE_SSL_ERROR(group != nullptr, "Failed to load EC_GROUP prime256v1");

        EC_POINT_ptr pubPoint(EC_POINT_new(group.get()), EC_POINT_free);
        HANDLE_SSL_ERROR(pubPoint != nullptr, "Failed to create EC_POINT");

        // 核心数学运算：将私钥 d 乘以曲线基点 G，结果存入 pubPoint
        HANDLE_SSL_ERROR(EC_POINT_mul(group.get(), pubPoint.get(), privBN.get(), nullptr, nullptr, nullptr) == 1, "Failed to compute Q = d * G");

        // 将算出的公钥点 (Q) 转换为标准的无压缩字节流 (Octet String)
        size_t pubBufLen = EC_POINT_point2oct(group.get(), pubPoint.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
        std::vector<unsigned char> pubBuf(pubBufLen);
        HANDLE_SSL_ERROR(EC_POINT_point2oct(group.get(), pubPoint.get(), POINT_CONVERSION_UNCOMPRESSED, pubBuf.data(), pubBufLen, nullptr) > 0, "Failed to convert public point");


        // =====================================================================
        // 3. 使用 OpenSSL 3.0 高级构建器 (OSSL_PARAM_BLD) 注入密钥对
        // =====================================================================
        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        HANDLE_SSL_ERROR(bld != nullptr, "Failed to create OSSL_PARAM_BLD");

        // 强行注入椭圆曲线名称、私钥 d，以及我们刚刚亲手算出来的公钥 Q
        HANDLE_SSL_ERROR(OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) == 1, "Failed to push group name");
        HANDLE_SSL_ERROR(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, privBN.get()) == 1, "Failed to push private key");
        HANDLE_SSL_ERROR(OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubBuf.data(), pubBuf.size()) == 1, "Failed to push public key");

        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        HANDLE_SSL_ERROR(params != nullptr, "Failed to convert params");

        // 4. 从包含完整公私钥的参数中恢复最终的 EVP_PKEY 密钥对
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
        HANDLE_SSL_ERROR(ctx != nullptr, "Failed to create ctx for fromdata");
        HANDLE_SSL_ERROR(EVP_PKEY_fromdata_init(ctx.get()) == 1, "Failed to init fromdata");

        EVP_PKEY* pkeyRaw = nullptr;
        HANDLE_SSL_ERROR(EVP_PKEY_fromdata(ctx.get(), &pkeyRaw, EVP_PKEY_KEYPAIR, params) == 1, "Failed to reconstruct pkey from seed");
        OSSL_PARAM_free(params);

        EVP_PKEY_ptr pkey(pkeyRaw, EVP_PKEY_free);

        // 5. 将提取的底层对象序列化为网络字节流
        unsigned char* pubKeyBytes = nullptr;
        int pubLen = i2d_PUBKEY(pkey.get(), &pubKeyBytes);
        HANDLE_SSL_ERROR(pubLen > 0, "Failed to serialize deterministic public key");
        kp.publicKey.assign(pubKeyBytes, pubKeyBytes + pubLen);
        OPENSSL_free(pubKeyBytes);

        unsigned char* privKeyBytes = nullptr;
        int privLen = i2d_PrivateKey(pkey.get(), &privKeyBytes);
        HANDLE_SSL_ERROR(privLen > 0, "Failed to serialize deterministic private key");
        kp.privateKey.assign(privKeyBytes, privKeyBytes + privLen);
        OPENSSL_free(privKeyBytes);

        return kp;
    }

} // namespace DeterministicECC