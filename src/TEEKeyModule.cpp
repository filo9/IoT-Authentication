#include "TEEKeyModule.h"
#include "CryptoModule.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <fstream>
#include <stdexcept>
#include <cstring>

// -------------------------------------------------------
// 内部辅助：PBKDF2-SHA256
// -------------------------------------------------------
static SecureBytes pbkdf2_sha256(const std::string& password,
                                 const uint8_t*     salt,
                                 size_t             saltLen,
                                 int                iterations,
                                 size_t             keyLen)
{
    SecureBytes out(keyLen);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                           static_cast<int>(password.size()),
                           salt, static_cast<int>(saltLen),
                           iterations,
                           EVP_sha256(),
                           static_cast<int>(keyLen),
                           out.data()) != 1)
    {
        throw std::runtime_error("TEEKeyModule: PBKDF2 failed");
    }
    return out;
}

// -------------------------------------------------------
// Enroll: 生成随机 salt → PBKDF2 派生 K → 持久化 salt
// -------------------------------------------------------
SecureBytes TEEKeyModule::Enroll(const std::string& deviceUID,
                                 const std::string& keystoreFile)
{
    // 1. 生成 16 字节随机 salt（对应 TPM 首次注入的种子）
    std::vector<uint8_t> salt(16);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("TEEKeyModule: RAND_bytes failed");
    }

    // 2. 持久化 salt（仅 salt 落盘，K 本身不存储）
    std::ofstream ofs(keystoreFile, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        throw std::runtime_error("TEEKeyModule: cannot write keystore: " + keystoreFile);
    }
    ofs.write(reinterpret_cast<const char*>(salt.data()),
              static_cast<std::streamsize>(salt.size()));
    ofs.close();

    // 3. 派生并返回 K
    return pbkdf2_sha256(deviceUID, salt.data(), salt.size(),
                         PBKDF2_ITERATIONS, KEY_BYTES);
}

// -------------------------------------------------------
// Derive: 读取 salt → PBKDF2 重新派生相同的 K
// -------------------------------------------------------
SecureBytes TEEKeyModule::Derive(const std::string& deviceUID,
                                 const std::string& keystoreFile)
{
    // 1. 读取 salt
    std::ifstream ifs(keystoreFile, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("TEEKeyModule: keystore not found: " + keystoreFile);
    }
    std::vector<uint8_t> salt(16);
    ifs.read(reinterpret_cast<char*>(salt.data()),
             static_cast<std::streamsize>(salt.size()));
    if (ifs.gcount() != 16) {
        throw std::runtime_error("TEEKeyModule: keystore corrupted");
    }
    ifs.close();

    // 2. 确定性重新派生
    return pbkdf2_sha256(deviceUID, salt.data(), salt.size(),
                         PBKDF2_ITERATIONS, KEY_BYTES);
}

// -------------------------------------------------------
// ComputeMasterKey: kmaster = HMAC-SHA256(K, pw || R)
// -------------------------------------------------------
SecureBytes TEEKeyModule::ComputeMasterKey(const SecureBytes&           deviceKey,
                                           const CryptoModule::Bytes&   password,
                                           const CryptoModule::Bytes&   bioSecret)
{
    // 组装 HMAC 输入：pw || R
    CryptoModule::Bytes input;
    input.insert(input.end(), password.begin(),  password.end());
    input.insert(input.end(), bioSecret.begin(), bioSecret.end());

    // HMAC-SHA256(K, pw || R)
    unsigned int outLen = 0;
    SecureBytes result(EVP_MAX_MD_SIZE);
    if (!HMAC(EVP_sha256(),
              deviceKey.data(), static_cast<int>(deviceKey.size()),
              input.data(),     static_cast<int>(input.size()),
              result.data(),    &outLen))
    {
        throw std::runtime_error("TEEKeyModule: HMAC failed");
    }
    result.resize(outLen);
    return result;
}
