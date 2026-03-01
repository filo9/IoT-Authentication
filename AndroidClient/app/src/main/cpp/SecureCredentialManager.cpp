#include "SecureCredentialManager.h"
#include "PUFModule.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <fstream>
#include <stdexcept>
#include <iostream>

#define HANDLE_SSL_ERROR(condition, msg) \
    if (!(condition)) { throw std::runtime_error(msg); }

// 析构函数：SecureBytes 会自动安全擦除 m_secure_k
SecureCredentialManager::~SecureCredentialManager() {
    // m_secure_k 的 SecureBytes 析构函数会自动调用 OPENSSL_cleanse
}

void SecureCredentialManager::GenerateAndWrapCredential(const std::string& deviceUID, const std::string& pin, const std::string& filepath) {
    // 1. 使用 PUF 生成硬件绑定的密钥 k
    PUFModule::PUFResponse pufResp = PUFModule::Enroll(deviceUID);
    m_secure_k = PUFModule::DeriveKeyFromPUF(pufResp.response);
    m_pufHelper = pufResp.helper;
    m_is_unlocked = true;

    // 2. 生成随机盐 (Salt)
    CryptoModule::Bytes salt(SALT_LENGTH);
    HANDLE_SSL_ERROR(RAND_bytes(salt.data(), salt.size()) == 1, "Failed to generate salt");

    // 3. PBKDF2 派生 KEK (Key Encryption Key)
    CryptoModule::Bytes kek(KEK_LENGTH);
    HANDLE_SSL_ERROR(PKCS5_PBKDF2_HMAC(pin.c_str(), pin.length(), 
                                       salt.data(), salt.size(), 
                                       PBKDF2_ITERATIONS, EVP_sha256(), 
                                       kek.size(), kek.data()) == 1, 
                     "PBKDF2 derivation failed");

    // 4. AES-128-GCM 加密 (Wrap k)
    CryptoModule::Bytes iv(IV_LENGTH);
    HANDLE_SSL_ERROR(RAND_bytes(iv.data(), iv.size()) == 1, "Failed to generate IV");

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    HANDLE_SSL_ERROR(EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, kek.data(), iv.data()) == 1, "Wrap init failed");

    CryptoModule::Bytes wrapped_k(m_secure_k.size() + EVP_CIPHER_block_size(EVP_aes_128_gcm()));
    int len = 0, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx.get(), wrapped_k.data(), &len, m_secure_k.data(), m_secure_k.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx.get(), wrapped_k.data() + len, &len);
    ciphertext_len += len;
    wrapped_k.resize(ciphertext_len);

    CryptoModule::Bytes tag(TAG_LENGTH);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag.data());

    // 5. 序列化持久化到文件结构： [Salt(16)] || [IV(12)] || [Tag(16)] || [Wrapped_k(32)] || [PUF_Helper(512)]
    std::ofstream outfile(filepath, std::ios::binary);
    HANDLE_SSL_ERROR(outfile.is_open(), "Failed to open keystore file for writing");
    outfile.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    outfile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    outfile.write(reinterpret_cast<const char*>(tag.data()), tag.size());
    outfile.write(reinterpret_cast<const char*>(wrapped_k.data()), wrapped_k.size());
    outfile.write(reinterpret_cast<const char*>(m_pufHelper.data()), m_pufHelper.size());
    outfile.close();

    // 内存安全：擦除临时派生的 KEK
    OPENSSL_cleanse(kek.data(), kek.size());
}

bool SecureCredentialManager::UnwrapAndLoadCredential(const std::string& deviceUID, const std::string& pin, const std::string& filepath) {
    // 1. 从文件读取加密包裹 + PUF 辅助数据
    std::ifstream infile(filepath, std::ios::binary);
    if (!infile.is_open()) return false;

    CryptoModule::Bytes salt(SALT_LENGTH), iv(IV_LENGTH), tag(TAG_LENGTH), wrapped_k(32);
    CryptoModule::Bytes pufHelper(512);
    infile.read(reinterpret_cast<char*>(salt.data()), SALT_LENGTH);
    infile.read(reinterpret_cast<char*>(iv.data()), IV_LENGTH);
    infile.read(reinterpret_cast<char*>(tag.data()), TAG_LENGTH);
    infile.read(reinterpret_cast<char*>(wrapped_k.data()), 32);
    infile.read(reinterpret_cast<char*>(pufHelper.data()), 512);
    infile.close();

    // 2. 使用 PUF 重构硬件密钥 k
    try {
        CryptoModule::Bytes pufResponse = PUFModule::Reconstruct(deviceUID, pufHelper);
        m_secure_k = PUFModule::DeriveKeyFromPUF(pufResponse);
        m_pufHelper = pufHelper;
    } catch (...) {
        return false;
    }

    // 2. 利用用户输入的 PIN 重新派生 KEK
    CryptoModule::Bytes kek(KEK_LENGTH);
    if (PKCS5_PBKDF2_HMAC(pin.c_str(), pin.length(), salt.data(), salt.size(),
                          PBKDF2_ITERATIONS, EVP_sha256(), kek.size(), kek.data()) != 1) {
        return false;
    }

    // 3. AES-128-GCM 解密并校验完整性
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, kek.data(), iv.data()) != 1) return false;

    CryptoModule::Bytes unwrapped_k(wrapped_k.size());
    int len = 0, plaintext_len = 0;
    EVP_DecryptUpdate(ctx.get(), unwrapped_k.data(), &len, wrapped_k.data(), wrapped_k.size());
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LENGTH, tag.data());

    // 如果 PIN 码错误或文件被篡改，这里的 Final 会返回 0
    if (EVP_DecryptFinal_ex(ctx.get(), unwrapped_k.data() + len, &len) != 1) {
        OPENSSL_cleanse(kek.data(), kek.size());
        return false;
    }
    plaintext_len += len;
    unwrapped_k.resize(plaintext_len);

    // 4. 验证 PUF 派生的 k 与解密出的 k 是否一致
    if (m_secure_k != unwrapped_k) {
        OPENSSL_cleanse(kek.data(), kek.size());
        OPENSSL_cleanse(unwrapped_k.data(), unwrapped_k.size());
        return false;
    }

    m_is_unlocked = true;

    // 安全擦除
    OPENSSL_cleanse(kek.data(), kek.size());
    return true;
}

CryptoModule::Bytes SecureCredentialManager::ComputeMasterKey(const CryptoModule::Bytes& pw, const CryptoModule::Bytes& feData_R) {
    if (!m_is_unlocked || m_secure_k.empty()) {
        throw std::runtime_error("Credential manager is locked. Please unlock with PIN first.");
    }
    
    // 委托底层进行 PRF 计算，外界拿不到 m_secure_k
    CryptoModule::Bytes prfInput = pw;
    prfInput.insert(prfInput.end(), feData_R.begin(), feData_R.end());
    
    return CryptoModule::PRF(m_secure_k, prfInput);
}