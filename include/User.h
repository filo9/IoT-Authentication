#pragma once

#include <string>
#include <vector>
#include "CryptoModule.h"
#include "BioModule.h"
#include "ProtocolMessages.h"
#include "SecureCredentialManager.h"
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

    // 实例化安全凭证管理器
    SecureCredentialManager m_secureManager;

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
    
    // ==========================================
    // 模拟获取安卓设备底层硬件指纹 (Hardware-bound ID)
    // ==========================================
    std::string GetDeviceHardwareID() const {
        // 在真实的 Android 移植中，这里会通过 JNI 调用获取系统层面的
        // ANDROID_ID, 或者是 TEE 内部的 Hardware Unique Key (HUK)。
        // 当前为 C++ 跨平台原型，我们返回一个与该物理设备强绑定的模拟特征字符串。
        return "HW_FINGERPRINT_A1B2C3D4_" + m_uid;
    }
};