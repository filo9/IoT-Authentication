#pragma once

#include <string>
#include <vector>
#include <sqlite3.h>
#include <unordered_map>
#include <ctime>
#include "CryptoModulePQC.h"
#include "ProtocolMessagesPQC.h"
#include "SecureRecordLayer.h"
#include "SecureBytes.h"

// 后量子认证失败记录
struct PQCAuthFailureRecord {
    int failCount;
    time_t lockUntil;
    time_t lastFailTime;
};

// 后量子性能统计结构
struct PQCPerformanceMetrics {
    // ML-KEM 操作耗时（微秒）
    double kemKeyGenTime = 0.0;
    double kemEncapsTime = 0.0;
    double kemDecapsTime = 0.0;

    // 其他密码学操作耗时（微秒）
    double signTime = 0.0;
    double verifyTime = 0.0;
    double encryptTime = 0.0;
    double decryptTime = 0.0;
    double hkdfTime = 0.0;
    double dbEncryptTime = 0.0;
    double dbDecryptTime = 0.0;

    // 协议阶段耗时（毫秒）
    double registrationTime = 0.0;
    double challengeGenTime = 0.0;
    double authVerifyTime = 0.0;
    double totalAuthTime = 0.0;

    // 统计计数器
    uint64_t totalAuthCount = 0;
    uint64_t successAuthCount = 0;
    uint64_t failedAuthCount = 0;

    // 数据大小（字节）— 用于对比
    size_t kemPublicKeySize = CryptoModulePQC::MLKEM768_PK_SIZE;
    size_t kemCiphertextSize = CryptoModulePQC::MLKEM768_CT_SIZE;
    size_t kemSharedSecretSize = CryptoModulePQC::MLKEM768_SS_SIZE;
};

// 后量子认证会话上下文
struct PQCAuthSession {
    CryptoModulePQC::KEMKeyPair tempKEM;     // 服务器的临时 ML-KEM 密钥对
    CryptoModule::Bytes serversigm;           // 服务器对 pk_KEM 的签名
    uint64_t timestamp;                      // 挑战下发时的时间戳
    CryptoModule::Bytes nonce;               // 挑战下发时的服务器随机数
    SecureBytes sharedSecret;
    SecureBytes sessionKey;
    SecureRecordLayer secureLayer;
};

class ServerPQC {
public:
    ServerPQC();
    ~ServerPQC();

    // ==========================================
    // 注册阶段 (与原协议一致)
    // ==========================================
    ProtocolMessagesPQC::RegistrationResponse ProcessRegistration(
        const ProtocolMessagesPQC::RegistrationRequest& req
    );

    // ==========================================
    // 后量子认证与密钥协商阶段
    // ==========================================

    // 步骤 2: 生成挑战 — 使用 ML-KEM 替代 ECDH
    ProtocolMessagesPQC::PQCAuthChallenge GenerateAuthChallenge(const std::string& uid);

    // 步骤 4: 处理客户端响应 — 使用 KEM.Decaps 替代 DH 协商
    ProtocolMessagesPQC::PQCAuthConfirmation ProcessAuthResponse(
        const ProtocolMessagesPQC::PQCAuthResponse& resp
    );

    CryptoModule::Bytes GetSessionKey(const std::string& uid) const;
    void HandleAuthFailure(const std::string& uid);
    PQCPerformanceMetrics GetPerformanceMetrics() const;
    void ExportPerformanceReport(const std::string& filepath) const;

    std::unordered_map<std::string, PQCAuthSession> m_activeSessions;
    std::unordered_map<std::string, PQCAuthFailureRecord> m_failureRecords;
    PQCPerformanceMetrics m_perfMetrics;

    void ClearDatabase();

private:
    CryptoModule::KeyPair m_longTermKeys;
    SecureBytes m_dbMasterKey;
    sqlite3* m_db = nullptr;

    void InitDatabase();
    CryptoModule::Bytes EncryptDBField(const CryptoModule::Bytes& plaintext);
    CryptoModule::Bytes DecryptDBField(const CryptoModule::Bytes& ciphertext);
};
