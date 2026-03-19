#pragma once

#include <string>
#include <vector>
#include "CryptoModulePQC.h"
#include "BioModule.h"
#include "ProtocolMessagesPQC.h"
#include "SecureCredentialManager.h"
#include "SecureBytes.h"

// 后量子客户端本地凭证
struct PQCClientCredential {
    CryptoModule::Bytes P;              // 模糊提取器辅助数据
    CryptoModule::Bytes pkEnc;          // 用户加密公钥
    CryptoModule::Bytes serversigpk;    // 服务器长期签名公钥
};

class UserPQC {
public:
    UserPQC(const std::string& uid) : m_uid(uid) {}

    // ==========================================
    // 注册阶段 (与原协议一致)
    // ==========================================
    ProtocolMessagesPQC::RegistrationRequest GenerateRegistrationRequest(
        const std::string& password,
        const CryptoModule::Bytes& biometric
    );

    void ProcessRegistrationResponse(const ProtocolMessagesPQC::RegistrationResponse& response);

    // ==========================================
    // 后量子认证与密钥协商阶段
    // ==========================================

    // 步骤 1: 发起登录请求
    ProtocolMessagesPQC::PQCAuthRequest InitiateAuthentication();

    // 步骤 3: 处理服务器挑战 — 使用 KEM.Encaps 替代 DH
    ProtocolMessagesPQC::PQCAuthResponse ProcessAuthChallenge(
        const ProtocolMessagesPQC::PQCAuthChallenge& challenge,
        const std::string& password,
        const CryptoModule::Bytes& currentBiometric
    );

    // 步骤 5: 最终确认
    bool FinalizeAuthentication(const ProtocolMessagesPQC::PQCAuthConfirmation& confirmation);

    CryptoModule::Bytes GetSessionKey() const { return m_sessionKey; }

    SecureCredentialManager m_secureManager;

private:
    std::string m_uid;
    PQCClientCredential m_ask;

    // 认证过程中的临时状态
    CryptoModule::Bytes m_kemCiphertext;   // KEM 密文 ct (替代 m_tempDH)
    CryptoModule::Bytes m_peerKEMPub;      // 服务器的 pk_KEM (替代 m_peerDHPub)
    uint64_t m_timestamp;
    CryptoModule::Bytes m_nonce;
    SecureBytes m_sharedSecret;
    CryptoModule::Bytes m_serverSigM;
    SecureBytes m_sessionKey;

    CryptoModule::Bytes m_tau;
    CryptoModule::Bytes m_tagU;

    std::string GetDeviceHardwareID() const {
        return "HW_FINGERPRINT_PQC_" + m_uid;
    }
};
