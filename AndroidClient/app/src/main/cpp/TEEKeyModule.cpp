#include "TEEKeyModule.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <fstream>
#include <stdexcept>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "TEEKeyModule", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "TEEKeyModule", __VA_ARGS__)

// -------------------------------------------------------
// JNI 回调注册（由 native-lib.cpp 在 JNI_OnLoad 中注册）
// -------------------------------------------------------
static TEEKeyModule::KeystoreHmacFn g_keystoreHmacFn = nullptr;

void TEEKeyModule::RegisterKeystoreHmacCallback(KeystoreHmacFn fn) {
    g_keystoreHmacFn = fn;
}

// -------------------------------------------------------
// 内部辅助：PBKDF2-SHA256（降级路径）
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
// 内部辅助：通过 Keystore 回调派生 K
//   K = Keystore.HMAC(hw_key, "tee_device_key_v1" || deviceUID)
// -------------------------------------------------------
static SecureBytes deriveViaKeystore(const std::string& deviceUID)
{
    const std::string keyAlias = "iot_auth_device_key";
    std::string info = "tee_device_key_v1" + deviceUID;
    std::vector<uint8_t> data(info.begin(), info.end());

    auto result = g_keystoreHmacFn(keyAlias, data);
    if (result.size() < TEEKeyModule::KEY_BYTES) {
        throw std::runtime_error("TEEKeyModule: Keystore HMAC returned insufficient bytes");
    }
    result.resize(TEEKeyModule::KEY_BYTES);

    SecureBytes k(result.begin(), result.end());
    OPENSSL_cleanse(result.data(), result.size());
    return k;
}

// -------------------------------------------------------
// Enroll
// -------------------------------------------------------
SecureBytes TEEKeyModule::Enroll(const std::string& deviceUID,
                                 const std::string& keystoreFile)
{
    if (g_keystoreHmacFn != nullptr) {
        // 【方案一】Android Keystore HMAC 路径
        // keystoreFile 写入一个标记，表明已使用 Keystore 路径
        std::ofstream ofs(keystoreFile, std::ios::binary | std::ios::trunc);
        if (ofs.is_open()) {
            const char marker[] = "KEYSTORE_PATH_V1";
            ofs.write(marker, sizeof(marker) - 1);
            ofs.close();
        }
        LOGI("✅ Enroll: 使用 Android Keystore TEE 路径");
        return deriveViaKeystore(deviceUID);
    }

    // 【方案四】降级路径：PBKDF2 + salt
    LOGI("⚠️  Enroll: Keystore 不可用，使用 PBKDF2 降级路径");
    std::vector<uint8_t> salt(16);
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("TEEKeyModule: RAND_bytes failed");
    }

    std::ofstream ofs(keystoreFile, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
        throw std::runtime_error("TEEKeyModule: cannot write keystore: " + keystoreFile);
    }
    // 降级路径标记 + salt
    const char fallbackMarker[] = "PBKDF2_PATH_V1__";  // 16字节
    ofs.write(fallbackMarker, 16);
    ofs.write(reinterpret_cast<const char*>(salt.data()),
              static_cast<std::streamsize>(salt.size()));
    ofs.close();

    return pbkdf2_sha256(deviceUID, salt.data(), salt.size(),
                         PBKDF2_ITERATIONS, KEY_BYTES);
}

// -------------------------------------------------------
// Derive
// -------------------------------------------------------
SecureBytes TEEKeyModule::Derive(const std::string& deviceUID,
                                 const std::string& keystoreFile)
{
    // 读取标记判断路径
    std::ifstream ifs(keystoreFile, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("TEEKeyModule: keystore not found: " + keystoreFile);
    }
    char marker[16] = {};
    ifs.read(marker, 16);
    ifs.close();

    const std::string markerStr(marker, 16);

    if (markerStr == "KEYSTORE_PATH_V1" && g_keystoreHmacFn != nullptr) {
        LOGI("✅ Derive: 使用 Android Keystore TEE 路径");
        return deriveViaKeystore(deviceUID);
    }

    if (markerStr.substr(0, 14) == "PBKDF2_PATH_V1") {
        // 读取 salt（标记后16字节）
        std::ifstream ifs2(keystoreFile, std::ios::binary);
        ifs2.seekg(16);
        std::vector<uint8_t> salt(16);
        ifs2.read(reinterpret_cast<char*>(salt.data()), 16);
        if (ifs2.gcount() != 16) {
            throw std::runtime_error("TEEKeyModule: keystore corrupted");
        }
        ifs2.close();
        LOGI("⚠️  Derive: 使用 PBKDF2 降级路径");
        return pbkdf2_sha256(deviceUID, salt.data(), salt.size(),
                             PBKDF2_ITERATIONS, KEY_BYTES);
    }

    throw std::runtime_error("TEEKeyModule: unknown keystore format");
}

// -------------------------------------------------------
// ComputeMasterKey: kmaster = HMAC-SHA256(K, pw || R)
// -------------------------------------------------------
SecureBytes TEEKeyModule::ComputeMasterKey(const SecureBytes&           deviceKey,
                                           const CryptoModule::Bytes&   password,
                                           const CryptoModule::Bytes&   bioSecret)
{
    CryptoModule::Bytes input;
    input.insert(input.end(), password.begin(),  password.end());
    input.insert(input.end(), bioSecret.begin(), bioSecret.end());

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
