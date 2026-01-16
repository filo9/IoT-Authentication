#pragma once

#include <string>
#include <vector>
#include <sqlite3.h>
#include <unordered_map>
#include <ctime>
#include "CryptoModule.h"
#include "ProtocolMessages.h"
#include "SecureRecordLayer.h"
#include "SecureBytes.h"

// 认证失败记录（用于指数退避和账户锁定）
struct AuthFailureRecord {
    int failCount;          // 连续失败次数
    time_t lockUntil;       // 锁定截止时间（Unix 秒）
    time_t lastFailTime;    // 最后一次失败时间
};

// 性能统计结构（用于论文性能分析）
struct PerformanceMetrics {
    // 各密码学操作耗时（微秒）
    double dhKeyGenTime = 0.0;
    double ecdhComputeTime = 0.0;
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

    // 内存占用（字节）
    size_t memoryUsage = 0;
};

// 模拟服务器数据库中存储的用户记录表 (avk)
struct UserRecord {
    CryptoModule::Bytes pkSig; // 用户的签名公钥 (用于验证用户身份)
    CryptoModule::Bytes skEnc; // 用户的解密私钥 (服务器托管，用于解密 tau)
};

// 维护认证过程中的临时会话上下文 (保证前向安全性)
struct AuthSession {
    CryptoModule::KeyPair tempDH;     // 服务器的临时 DH 密钥对 (dhprivS, dhpubS)
    CryptoModule::Bytes serversigm;   // 服务器对 DH 公钥的签名
    uint64_t timestamp;               // 挑战下发时的时间戳
    CryptoModule::Bytes nonce;        // 挑战下发时的服务器随机数
    SecureBytes sharedSecret;         // 协商出的共享秘密（安全擦除）
    SecureBytes sessionKey;           // 最终派生的会话密钥（安全擦除）
    SecureRecordLayer secureLayer;
};

class Server {
public:
    // 初始化服务器，生成长期签名密钥对 [cite: 144-146]
    Server();
    ~Server();
    // ==========================================
    // 注册阶段
    // ==========================================
    
    // 处理用户注册请求，将 avk 存入数据库，并返回服务器长期公钥 [cite: 163-166]
    ProtocolMessages::RegistrationResponse ProcessRegistration(
        const ProtocolMessages::RegistrationRequest& req
    );

    // ==========================================
    // 认证与密钥协商阶段
    // ==========================================
    
    // 步骤 2: 响应用户的登录请求，生成并下发挑战 (包含临时 DH 公钥和签名) [cite: 175-178]
    ProtocolMessages::AuthChallenge GenerateAuthChallenge(const std::string& uid);

    // 步骤 4: 接收用户的响应，执行解密、验签、共享秘密计算与标签确认 [cite: 192-201]
    ProtocolMessages::AuthConfirmation ProcessAuthResponse(
        const ProtocolMessages::AuthResponse& resp
    );

    // 获取特定用户的会话密钥 (用于测试验证)
    CryptoModule::Bytes GetSessionKey(const std::string& uid) const;

    // 处理认证失败：更新失败计数器和锁定时间
    void HandleAuthFailure(const std::string& uid);

    // 获取性能统计数据（用于 Web 大屏实时展示）
    PerformanceMetrics GetPerformanceMetrics() const;

    // 导出性能报告到 CSV（用于论文绘图）
    void ExportPerformanceReport(const std::string& filepath) const;

// 模拟内存缓存：uid -> AuthSession (当前正在进行的认证会话)
    std::unordered_map<std::string, AuthSession> m_activeSessions;

    // 认证失败记录：uid -> AuthFailureRecord
    std::unordered_map<std::string, AuthFailureRecord> m_failureRecords;

    // 性能统计数据
    PerformanceMetrics m_perfMetrics;

    // 专为测试流程设计的：清空数据库
    void ClearDatabase();

private:
    // 服务器的长期身份密钥
    CryptoModule::KeyPair m_longTermKeys;

    // 数据库主密钥（用于加密 skEnc 字段）
    SecureBytes m_dbMasterKey;

    // 模拟数据库：uid -> UserRecord (avk)
    //std::unordered_map<std::string, UserRecord> m_database;



    //数据库连接句柄
    sqlite3* m_db = nullptr;

    //内部辅助函数：初始化数据库建表
    void InitDatabase();

    // 数据库字段加密/解密辅助函数
    CryptoModule::Bytes EncryptDBField(const CryptoModule::Bytes& plaintext);
    CryptoModule::Bytes DecryptDBField(const CryptoModule::Bytes& ciphertext);
};