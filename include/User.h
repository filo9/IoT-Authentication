#pragma once

#include <string>
#include <vector>
#include "CryptoModule.h"
#include "BioModule.h"
#include "ProtocolMessages.h"
#include "TEEKeyModule.h"
#include "SecureBytes.h"


// 用户本地存储的凭证结构 (ask) [cite: 169]
struct ClientCredential {
    CryptoModule::Bytes P;              // 模糊提取器的辅助数据
    CryptoModule::Bytes pkEnc;          // 用户的加密公钥
    CryptoModule::Bytes serversigpk;    // 服务器的长期签名公钥
};

class User {
public:
    User(const std::string& uid) : m_uid(uid) {}

    // ==========================================
    // 注册阶段 (Registration)
    // ==========================================
    
    // 生成发送给服务器的注册包 (avk) [cite: 152-162]
    ProtocolMessages::RegistrationRequest GenerateRegistrationRequest(
        const std::string& password, 
        const CryptoModule::Bytes& biometric
    );

    // 处理服务器返回的注册响应，保存本地凭证 (ask) [cite: 168-169]
    void ProcessRegistrationResponse(const ProtocolMessages::RegistrationResponse& response);

    // ==========================================
    // 认证与密钥协商阶段 (Authentication)
    // ==========================================
    
    // 步骤 1: 发起登录请求 [cite: 173-174]
    ProtocolMessages::AuthRequest InitiateAuthentication();

    // 步骤 3: 处理服务器挑战，验证服务器并生成用户响应 [cite: 179-191]
    ProtocolMessages::AuthResponse ProcessAuthChallenge(
        const ProtocolMessages::AuthChallenge& challenge,
        const std::string& password,
        const CryptoModule::Bytes& currentBiometric // bio'
    );

    // 步骤 5: 最终确认，验证服务器的 tagS 并导出最终会话密钥 [cite: 202-206]
    bool FinalizeAuthentication(const ProtocolMessages::AuthConfirmation& confirmation);

    // 获取协商成功的最终会话密钥
    CryptoModule::Bytes GetSessionKey() const { return m_sessionKey; }

private:
    std::string m_uid;
    ClientCredential m_ask; // 存储在本地的凭证，不含私钥明文

    // 认证过程中的临时会话状态（敏感数据使用 SecureBytes 自动擦除）
    CryptoModule::KeyPair m_tempDH;
    CryptoModule::Bytes m_peerDHPub;
    uint64_t m_timestamp;
    CryptoModule::Bytes m_nonce;
    SecureBytes m_sharedSecret;
    CryptoModule::Bytes m_serverSigM;
    SecureBytes m_sessionKey;

    //保存客户端生成的包，供最后一步验证服务器 tagS 使用
    CryptoModule::Bytes m_tau;
    CryptoModule::Bytes m_tagU;
};