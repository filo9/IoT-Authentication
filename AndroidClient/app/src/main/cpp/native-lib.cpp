#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <openssl/evp.h>
#include <fstream>
#include <random>
#include "json.hpp"
#include "User.h"
#include <functional>
#include "BioModule.h"
#include <android/log.h>
#define LOG_TAG "IoT_Auth_Native"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
// 全局设备指针与存储路径声明
std::unique_ptr<User> g_device = nullptr;
std::string g_storagePath = "";
std::string g_currentUid = "";

using json = nlohmann::json;

// =========================================================
// 【新增】：UID 虚拟映射引擎
// 将任意字符串 UID 稳定映射到 FVC2002 物理库的 101~110 之间
// =========================================================
std::string MapUidToFvcId(const std::string& uid) {
    if (uid.empty()) return "101"; // 兜底保护
    size_t hash_val = std::hash<std::string>{}(uid);
    int fvc_id = 101 + (hash_val % 10);
    return std::to_string(fvc_id);
}
// 修改 native-lib.cpp 中的解码函数
std::vector<uint8_t> Base64Decode(const std::string& input) {
    if (input.empty()) return {};
    // 预估长度
    std::vector<uint8_t> decoded(input.size());
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);

    int outl = 0;
    int totall = 0;
    // 解码主体
    if (EVP_DecodeUpdate(ctx, decoded.data(), &outl,
                         reinterpret_cast<const uint8_t*>(input.data()), input.size()) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return {};
    }
    totall = outl;
    // 处理收尾（关键：这步会根据 '=' 处理正确的长度）
    if (EVP_DecodeFinal(ctx, decoded.data() + outl, &outl) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return {};
    }
    totall += outl;
    decoded.resize(totall);
    EVP_ENCODE_CTX_free(ctx);
    return decoded;
}
std::string Base64Encode(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) return "";
    std::vector<uint8_t> encoded(4 * ((buffer.size() + 2) / 3) + 1);
    int len = EVP_EncodeBlock(encoded.data(), buffer.data(), buffer.size());
    return std::string(encoded.begin(), encoded.begin() + len);
}

// ---------------------------------------------------------
// 辅助函数: 字节数组转十六进制字符串
// 采用模板定义以兼容 BioModule::Bytes 与 CryptoModule::Bytes
// 必须放置在所有 JNI 函数之前，以确保编译器可见性
// ---------------------------------------------------------
template <typename T>
std::string BytesToHex(const T& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ---------------------------------------------------------
// JNI 接口 1：初始化设备与路径
// ---------------------------------------------------------
extern "C" JNIEXPORT jboolean JNICALL
Java_com_filo_iotauth_MainActivity_initDevice(JNIEnv* env, jobject /* this */, jstring uid_, jstring path_) {
    if (uid_ == nullptr || path_ == nullptr) {
        return JNI_FALSE;
    }

    const char* uid = env->GetStringUTFChars(uid_, 0);
    const char* path = env->GetStringUTFChars(path_, 0);

    // 确保路径以斜杠结尾
    std::string storageStr(path);
    if (!storageStr.empty() && storageStr.back() != '/') {
        storageStr += "/";
    }
    g_storagePath = storageStr;

    std::string uidStr(uid);

    env->ReleaseStringUTFChars(uid_, uid);
    env->ReleaseStringUTFChars(path_, path);

    try {
        // 【核心修复】：判断如果 UID 变了，必须销毁旧对象，重新创建！
        if (g_device != nullptr) {
            if (g_currentUid == uidStr) {
                LOGE("Device %s already initialized in memory. Reusing it.", uidStr.c_str());
                return JNI_TRUE;
            } else {
                LOGE("UID changed from %s to %s. Rebuilding device object...", g_currentUid.c_str(), uidStr.c_str());
                g_device.reset(); // 销毁旧的，释放内存
            }
        }

        g_device = std::make_unique<User>(uidStr);
        g_currentUid = uidStr; // 更新当前绑定的 UID
        return JNI_TRUE;
    } catch (...) {
        return JNI_FALSE;
    }
}

// ---------------------------------------------------------
// JNI 接口 2：生成注册请求包
// ---------------------------------------------------------
extern "C" JNIEXPORT jstring JNICALL
Java_com_filo_iotauth_MainActivity_generateRegisterPayload(JNIEnv* env, jobject /* this */, jstring pwd_) {
    if (!g_device) return env->NewStringUTF("{\"error\": \"Device not initialized\"}");

    const char* pwd = env->GetStringUTFChars(pwd_, 0);
    std::string password(pwd);
    env->ReleaseStringUTFChars(pwd_, pwd);

    try {
        // ================= 【核心替换：读取真实的物理基准特征】 =================
        // 目标文件格式：存储路径/fingerprint_features/101_1_vault.dat
        // 将用户的真实 UID 映射为底层物理指纹 ID
        std::string mappedFvcId = MapUidToFvcId(g_currentUid);
        std::string bio_file = g_storagePath + "fingerprint_features/" + mappedFvcId + "_1_vault.dat";
        std::ifstream bioIn(bio_file, std::ios::binary);

        if (!bioIn.is_open()) {
            std::string err = "{\"error\": \"找不到基准指纹: " + bio_file + "\"}";
            return env->NewStringUTF(err.c_str());
        }

        // 神经密码学特征固定为 512个float = 2048 bytes
        BioModule::Bytes realBio(2048, 0);
        bioIn.read(reinterpret_cast<char*>(realBio.data()), 2048);
        bioIn.close();
        LOGE("✅ 注册阶段：成功加载物理基准指纹 -> %s", bio_file.c_str());

        // 调用状态机生成注册包 (此时传入的是真实 2048 字节特征)
        ProtocolMessages::RegistrationRequest req = g_device->GenerateRegistrationRequest(password, realBio);

        // ... 下面的序列化 JSON 逻辑保持不变 ...
        std::string regJson = "{\n"
                              "  \"uid\": \"" + req.uid + "\",\n"
                                                          "  \"avk_pkSig\": \"" + BytesToHex(req.avk_pkSig) + "\",\n"
                                                                                                              "  \"avk_skEnc\": \"" + BytesToHex(req.avk_skEnc) + "\"\n"
                                                                                                                                                                  "}";

        return env->NewStringUTF(regJson.c_str());
    } catch (const std::exception& e) {
        std::string err = std::string("{\"error\": \"") + e.what() + "\"}";
        return env->NewStringUTF(err.c_str());
    }
}

// ---------------------------------------------------------
// JNI 接口 3：处理服务器注册响应 (JSON解析 -> Base64解码 -> 触发落盘)
// ---------------------------------------------------------
extern "C" JNIEXPORT jboolean JNICALL
Java_com_filo_iotauth_MainActivity_processServerResponse(JNIEnv* env, jobject /* this */, jstring jsonResponse_) {
    if (!g_device) return JNI_FALSE;

    const char* jsonResponse = env->GetStringUTFChars(jsonResponse_, 0);
    std::string respStr(jsonResponse);
    env->ReleaseStringUTFChars(jsonResponse_, jsonResponse);

    try {
        // 1. C++ 层解析 JSON
        auto j = json::parse(respStr);

        // 2. 校验服务器状态码
        if (j.contains("status") && j["status"] == "success") {
            // 3. 提取 Base64 字符串并进行底层解码
            std::string b64_pk = j["serversigpk"];
            CryptoModule::Bytes pkBytes = Base64Decode(b64_pk);

            // 4. 构造 C++ 层的结构体
            ProtocolMessages::RegistrationResponse resp;
            resp.success = true;
            resp.serversigpk = pkBytes;
            LOGE("Received PK: %s", b64_pk.c_str());
            // 5. 状态机流转：触发落盘和内存状态更新
            g_device->ProcessRegistrationResponse(resp);
            return JNI_TRUE;
        }
        return JNI_FALSE;
    } catch (const std::exception& e) {
        // 如果 JSON 格式不对，或者文件写入失败，拦截异常防崩溃
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_filo_iotauth_MainActivity_testBioExtraction(JNIEnv* env, jobject /* this */) {
    try {
        // 1. 调用你写的模拟器：生成 64 字节的原始指纹
        BioModule::Bytes mockBio = BioModule::GenerateMockBiometric(64);

        // 2. 扔进模糊提取器，生成高熵密钥 R 和辅助数据 P
        BioModule::FuzzyExtractorData feData = BioModule::Gen(mockBio);

        // 3. 把提取结果拼装成人类可读的字符串，准备发给安卓界面
        std::string result = "【生物特征提取成功】\n\n";

        result += "👉 原始指纹采样 (前8字节):\n";
        result += BytesToHex(BioModule::Bytes(mockBio.begin(), mockBio.begin() + 8)) + "...\n\n";

        result += "🔐 提取的高熵种子 R (32字节):\n";
        result += BytesToHex(feData.R) + "\n\n";

        result += "📦 辅助纠错数据 P (64字节):\n";
        result += BytesToHex(feData.P) + "\n";

        // 将 C++ 的 std::string 转换为 Java 的 String 并返回
        return env->NewStringUTF(result.c_str());

    } catch (const std::exception& e) {
        // 如果你的 ReedSolomon 引擎或者 OpenSSL 报错了，会直接把错误信息抛到手机屏幕上
        std::string errorMsg = std::string("提取失败: ") + e.what();
        return env->NewStringUTF(errorMsg.c_str());
    }
}
// =========================================================
// 【新增】JNI 接口 4：处理服务器的认证挑战 (Challenge)
// =========================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_filo_iotauth_MainActivity_processAuthChallenge(
        JNIEnv* env, jobject thiz,
        jstring uid_, jstring pwd_,
        jstring dhpubSBase64_, jstring serverSigMBase64_,
        jlong timestamp_, jstring nonceBase64_, // 新增接收参数
        jboolean is_bio_success) {

    if (!g_device) return env->NewStringUTF("{\"error\": \"Device not initialized\"}");

    const char* uid = env->GetStringUTFChars(uid_, 0);
    const char* pwd = env->GetStringUTFChars(pwd_, 0);
    const char* dhpubS = env->GetStringUTFChars(dhpubSBase64_, 0);
    const char* serverSig = env->GetStringUTFChars(serverSigMBase64_, 0);
    const char* nonceStr = env->GetStringUTFChars(nonceBase64_, 0);

    std::string uidStr(uid);
    std::string pwdStr(pwd);
    std::string dhpubSStr(dhpubS);
    std::string serverSigStr(serverSig ? serverSig : "");
    std::string nonce(nonceStr);

    env->ReleaseStringUTFChars(uid_, uid);
    env->ReleaseStringUTFChars(pwd_, pwd);
    env->ReleaseStringUTFChars(dhpubSBase64_, dhpubS);
    env->ReleaseStringUTFChars(serverSigMBase64_, serverSig);
    env->ReleaseStringUTFChars(nonceBase64_, nonceStr);

    try {
        LOGE("开始执行 Java 层验签...");

        // --- 提取公钥部分保持不变 ---
        std::string pkBase64 = "";
        if (!g_device->m_ask.serversigpk.empty()) {
            pkBase64 = Base64Encode(g_device->m_ask.serversigpk);
        } else {
            std::string pubkey_file = g_storagePath + "server_pk.dat";
            std::ifstream infile(pubkey_file, std::ios::binary | std::ios::ate);
            if (infile.is_open()) {
                std::streamsize size = infile.tellg();
                infile.seekg(0, std::ios::beg);
                std::vector<uint8_t> pk(size);
                infile.read(reinterpret_cast<char*>(pk.data()), size);
                pkBase64 = Base64Encode(pk);
            } else {
                return env->NewStringUTF("{\"error\": \"Server public key not found!\"}");
            }
        }

        // ==========================================
        // 【核心修复】：拼装完整的防重放签名原文
        // ==========================================
        std::vector<uint8_t> dhpubSBytes = Base64Decode(dhpubSStr);
        std::vector<uint8_t> nonceBytes = Base64Decode(nonce);

        // 原文组装：dhpubS || timestamp(8字节大端序) || nonce
        std::vector<uint8_t> sigInput = dhpubSBytes;
        for (int i = 7; i >= 0; --i) {
            sigInput.push_back(static_cast<uint8_t>((timestamp_ >> (i * 8)) & 0xFF));
        }
        sigInput.insert(sigInput.end(), nonceBytes.begin(), nonceBytes.end());

        // 将组装好的完整原文转成 Base64 传给 Java 层
        std::string fullMessageBase64 = Base64Encode(sigInput);

        jclass clazz = env->GetObjectClass(thiz);
        jmethodID verifyMethod = env->GetMethodID(clazz, "verifySignatureInJava", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z");

        jstring jPkBase64 = env->NewStringUTF(pkBase64.c_str());
        jstring jMessageBase64 = env->NewStringUTF(fullMessageBase64.c_str()); // 传入完整 Message
        jstring jSignatureBase64 = env->NewStringUTF(serverSigStr.c_str());

        jboolean isVerified = env->CallBooleanMethod(thiz, verifyMethod, jPkBase64, jMessageBase64, jSignatureBase64);

        env->DeleteLocalRef(jPkBase64);
        env->DeleteLocalRef(jMessageBase64);
        env->DeleteLocalRef(jSignatureBase64);
        env->DeleteLocalRef(clazz);

        if (!isVerified) {
            LOGE("❌ Java 层验签判定失败！");
            return env->NewStringUTF("{\"error\": \"Server signature verification failed! Possible MITM attack.\"}");
        }
        LOGE("✅ Java 层验签通过，继续 C++ 核心流程...");

        // ==========================================
        // 构造 C++ 层的结构体，注意加上缺失的时间戳和 Nonce！
        // ==========================================
        ProtocolMessages::AuthChallenge challenge;
        challenge.dhpubS = dhpubSBytes;
        challenge.serversigm = Base64Decode(serverSigStr);
        challenge.timestamp = static_cast<uint64_t>(timestamp_); // 必须填！
        challenge.nonce = nonceBytes;                            // 必须填！

        // --- 以下探针特征提取逻辑保持不变 ---
        BioModule::Bytes currentBio(2048, 0);

        if (is_bio_success) {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(2, 7);
            int probeIndex = distrib(gen);

            std::string mappedFvcId = MapUidToFvcId(g_currentUid);
            std::string bio_file = g_storagePath + "fingerprint_features/" + mappedFvcId + "_" + std::to_string(probeIndex) + "_vault.dat";
            std::ifstream bioIn(bio_file, std::ios::binary);

            if (bioIn.is_open()) {
                bioIn.read(reinterpret_cast<char*>(currentBio.data()), 2048);
                bioIn.close();
                LOGE("✅ 认证阶段：成功加载物理探针 -> %s (Mapped from %s)", bio_file.c_str(), g_currentUid.c_str());
            } else {
                return env->NewStringUTF("{\"error\": \"找不到探针指纹，请确认Assets释放成功。\"}");
            }
        } else {
            LOGE("💀 触发防御：指纹错配，直接喂给模糊提取器纯垃圾数据！");
            currentBio = BioModule::GenerateMockBiometric(2048);
        }

        ProtocolMessages::AuthResponse resp = g_device->ProcessAuthChallenge(challenge, pwdStr, currentBio);

        json resultJson;
        resultJson["uid"] = uidStr;
        resultJson["tau"] = Base64Encode(resp.tau);
        resultJson["tagU"] = Base64Encode(resp.tagU);

        return env->NewStringUTF(resultJson.dump().c_str());

    } catch (const std::exception& e) {
        LOGE("底层密码学异常: %s", e.what());
        std::string err = std::string("{\"error\": \"") + e.what() + "\"}";
        return env->NewStringUTF(err.c_str());
    }
}// =========================================================
// JNI 接口 5：处理服务器的最终确认 (Finalize)
// =========================================================
extern "C" JNIEXPORT jboolean JNICALL
Java_com_filo_iotauth_MainActivity_finalizeAuth(
        JNIEnv* env, jobject thiz, jstring tagSBase64_, jstring serverSigTagBase64_) {

    if (!g_device) return JNI_FALSE;

    const char* tagS = env->GetStringUTFChars(tagSBase64_, 0);
    const char* serverSigTag = env->GetStringUTFChars(serverSigTagBase64_, 0);

    std::string tagSStr(tagS);
    std::string serverSigTagStr(serverSigTag);

    env->ReleaseStringUTFChars(tagSBase64_, tagS);
    env->ReleaseStringUTFChars(serverSigTagBase64_, serverSigTag);

    try {
        std::string pkBase64 = "";
        if (!g_device->m_ask.serversigpk.empty()) {
            pkBase64 = Base64Encode(g_device->m_ask.serversigpk);
        } else {
            std::string pubkey_file = g_storagePath + "server_pk.dat";
            std::ifstream infile(pubkey_file, std::ios::binary | std::ios::ate);
            if (infile.is_open()) {
                std::streamsize size = infile.tellg();
                infile.seekg(0, std::ios::beg);
                std::vector<uint8_t> pk(size);
                infile.read(reinterpret_cast<char*>(pk.data()), size);
                pkBase64 = Base64Encode(pk);
            } else {
                return JNI_FALSE;
            }
        }

        jclass clazz = env->GetObjectClass(thiz);
        jmethodID verifyMethod = env->GetMethodID(clazz, "verifySignatureInJava", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z");

        if (verifyMethod == nullptr) return JNI_FALSE;

        jstring jPkBase64 = env->NewStringUTF(pkBase64.c_str());
        jstring jMessageBase64 = env->NewStringUTF(tagSStr.c_str());
        jstring jSignatureBase64 = env->NewStringUTF(serverSigTagStr.c_str());

        jboolean isVerified = env->CallBooleanMethod(thiz, verifyMethod, jPkBase64, jMessageBase64, jSignatureBase64);

        env->DeleteLocalRef(jPkBase64);
        env->DeleteLocalRef(jMessageBase64);
        env->DeleteLocalRef(jSignatureBase64);
        env->DeleteLocalRef(clazz);

        if (!isVerified) {
            LOGE("❌ Finalize阶段：Java层验证网关最终确认签名失败！");
            return JNI_FALSE;
        }

        ProtocolMessages::AuthConfirmation confirm;
        confirm.success = true;
        confirm.tagS = Base64Decode(tagSStr);
        confirm.serversigtag = Base64Decode(serverSigTagStr);

        bool result = g_device->FinalizeAuthentication(confirm);
        return result ? JNI_TRUE : JNI_FALSE;

    } catch (...) {
        return JNI_FALSE;
    }
} // <========== 就是漏了这一个非常致命的右大括号！

// =========================================================
// JNI 接口 6：加密业务指令
// =========================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_filo_iotauth_MainActivity_encryptCommand(JNIEnv* env, jobject /* this */, jstring plaintextCmd_) {
    if (!g_device) return env->NewStringUTF("{\"error\": \"Device not initialized\"}");

    const char* plaintext = env->GetStringUTFChars(plaintextCmd_, 0);
    std::string plainStr(plaintext);
    env->ReleaseStringUTFChars(plaintextCmd_, plaintext);

    try {
        CryptoModule::Bytes ciphertext = g_device->m_secureLayer.ProtectRecord(plainStr);
        return env->NewStringUTF(Base64Encode(ciphertext).c_str());
    } catch (const std::exception& e) {
        LOGE("加密业务指令失败: %s", e.what());
        return env->NewStringUTF("");
    }
}

// =========================================================
// JNI 接口 7：解密网关回执
// =========================================================
extern "C" JNIEXPORT jstring JNICALL
Java_com_filo_iotauth_MainActivity_decryptResponse(JNIEnv* env, jobject /* this */, jstring ciphertextB64_) {
    if (!g_device) return env->NewStringUTF("{\"error\": \"Device not initialized\"}");

    const char* cipherB64 = env->GetStringUTFChars(ciphertextB64_, 0);
    std::string cipherStr(cipherB64);
    env->ReleaseStringUTFChars(ciphertextB64_, cipherB64);

    try {
        CryptoModule::Bytes ciphertext = Base64Decode(cipherStr);
        std::string plaintext = g_device->m_secureLayer.UnprotectRecord(ciphertext);
        return env->NewStringUTF(plaintext.c_str());
    } catch (const std::exception& e) {
        LOGE("🛑 解密网关回执失败 (可能遭遇篡改或重放): %s", e.what());
        return env->NewStringUTF("");
    }
}