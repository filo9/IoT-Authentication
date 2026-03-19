#include "UserPQC.h"
#include "DeterministicECC.h"
#include "SecureBytes.h"
#include <openssl/crypto.h>
#include <stdexcept>
#include <iostream>
#include <chrono>

// ==========================================
// 注册阶段 (与原协议逻辑一致)
// ==========================================
ProtocolMessagesPQC::RegistrationRequest UserPQC::GenerateRegistrationRequest(
    const std::string& password,
    const CryptoModule::Bytes& biometric)
{
    // 1. 生物特征处理
    auto feData = BioModule::Gen(biometric);

    // 2. PUF 密钥生成
    std::string device_pin = GetDeviceHardwareID();
    std::string keystore_file = "user_pqc_" + m_uid + "_keystore.dat";
    m_secureManager.GenerateAndWrapCredential(m_uid, device_pin, keystore_file);

    // 3. 主密钥派生: kmaster = F(k, pw || R)
    CryptoModule::Bytes pwBytes(password.begin(), password.end());
    SecureBytes kmaster = m_secureManager.ComputeMasterKey(pwBytes, feData.R);

    // 4. 确定性生成签名密钥对
    auto sigKeyPair = DeterministicECC::DeriveKeyPairFromSeed(kmaster);
    struct SigKeyGuard {
        CryptoModule::KeyPair& kp;
        ~SigKeyGuard() { OPENSSL_cleanse(kp.privateKey.data(), kp.privateKey.size()); }
    } sigGuard{sigKeyPair};

    // 5. 生成加密密钥对
    auto encKeyPair = CryptoModulePQC::GenerateEncryptionKeyPair();

    // 6. 保存本地凭证
    m_ask.P = feData.P;
    m_ask.pkEnc = encKeyPair.publicKey;

    // 7. 构造注册包
    ProtocolMessagesPQC::RegistrationRequest req;
    req.uid = m_uid;
    req.avk_pkSig = sigKeyPair.publicKey;
    req.avk_skEnc = encKeyPair.privateKey;

    return req;
}

void UserPQC::ProcessRegistrationResponse(const ProtocolMessagesPQC::RegistrationResponse& response) {
    if (!response.success) throw std::runtime_error("[PQC] Registration failed on server.");
    m_ask.serversigpk = response.serversigpk;
}

// ==========================================
// 认证与密钥协商阶段
// ==========================================
ProtocolMessagesPQC::PQCAuthRequest UserPQC::InitiateAuthentication() {
    ProtocolMessagesPQC::PQCAuthRequest req;
    req.uid = m_uid;
    return req;
}

// ==========================================
// 步骤 3: 处理服务器挑战 — KEM.Encaps 替代 DH
// ==========================================
ProtocolMessagesPQC::PQCAuthResponse UserPQC::ProcessAuthChallenge(
    const ProtocolMessagesPQC::PQCAuthChallenge& challenge,
    const std::string& password,
    const CryptoModule::Bytes& currentBiometric)
{
    // 1. 验证时间戳新鲜性（30 秒窗口）
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t currentTime = static_cast<uint64_t>(ms);

    const uint64_t TIME_WINDOW_MS = 30000;
    if (currentTime < challenge.timestamp || currentTime - challenge.timestamp > TIME_WINDOW_MS) {
        throw std::runtime_error("[PQC] Challenge timestamp expired! Possible replay attack.");
    }

    // 2. 验证服务器签名: Verify(server_pk, pk_KEM, server_sigm)
    if (!CryptoModulePQC::VerifySignature(m_ask.serversigpk, challenge.pkKEM, challenge.serversigm)) {
        throw std::runtime_error("[PQC] Server signature verification failed! Possible MITM attack.");
    }

    // 保存上下文
    m_peerKEMPub = challenge.pkKEM;
    m_serverSigM = challenge.serversigm;
    m_timestamp = challenge.timestamp;
    m_nonce = challenge.nonce;
    // 3. 恢复生物特征 R
    CryptoModule::Bytes R = BioModule::Rep(currentBiometric, m_ask.P);
    if (R.empty()) {
        throw std::runtime_error("[PQC] Biometric mismatch! Authentication aborted.");
    }

    // 4. 恢复主密钥 kmaster
    std::string device_pin = GetDeviceHardwareID();
    std::string keystore_file = "user_pqc_" + m_uid + "_keystore.dat";
    if (!m_secureManager.UnwrapAndLoadCredential(m_uid, device_pin, keystore_file)) {
        throw std::runtime_error("[PQC] PUF reconstruction failed!");
    }

    CryptoModule::Bytes pwBytes(password.begin(), password.end());
    SecureBytes kmaster = m_secureManager.ComputeMasterKey(pwBytes, R);

    // 5. 确定性重构签名密钥对
    auto sigKeyPair = DeterministicECC::DeriveKeyPairFromSeed(kmaster);
    struct SigKeyGuard {
        CryptoModule::KeyPair& kp;
        ~SigKeyGuard() { OPENSSL_cleanse(kp.privateKey.data(), kp.privateKey.size()); }
    } sigGuard{sigKeyPair};

    // 6. 后量子密钥封装 (替代 DH 密钥生成 + 共享秘密计算)
    // (ct, shared_secret) <- ML-KEM.Encaps(pk_KEM)
    auto kemResult = CryptoModulePQC::KEM_Encaps(challenge.pkKEM);
    m_kemCiphertext = kemResult.ciphertext;
    m_sharedSecret = kemResult.sharedSecret;

    // 7. 生成用户确认标签
    // tagU = H(shared_secret || uid || pk_KEM || timestamp || nonce_S || server_sigm || ct || "clientconfirm")
    CryptoModule::Bytes tagInput = m_sharedSecret;
    tagInput.insert(tagInput.end(), m_uid.begin(), m_uid.end());
    tagInput.insert(tagInput.end(), challenge.pkKEM.begin(), challenge.pkKEM.end());

    // 将 timestamp 按大端序序列化为 8 字节加入
    for (int i = 7; i >= 0; --i) {
        tagInput.push_back(static_cast<uint8_t>((challenge.timestamp >> (i * 8)) & 0xFF));
    }
    // 加入 nonce_S
    tagInput.insert(tagInput.end(), challenge.nonce.begin(), challenge.nonce.end());

    tagInput.insert(tagInput.end(), challenge.serversigm.begin(), challenge.serversigm.end());
    tagInput.insert(tagInput.end(), m_kemCiphertext.begin(), m_kemCiphertext.end());
    std::string confirmStr = "clientconfirm";
    tagInput.insert(tagInput.end(), confirmStr.begin(), confirmStr.end());

    CryptoModule::Bytes tagU = CryptoModulePQC::Hash(tagInput);

    // 8. 用户签名: sigma = Sign(skSig, (uid, pk_KEM, ct, tagU))
    CryptoModule::Bytes sigInput(m_uid.begin(), m_uid.end());
    sigInput.insert(sigInput.end(), challenge.pkKEM.begin(), challenge.pkKEM.end());
    sigInput.insert(sigInput.end(), m_kemCiphertext.begin(), m_kemCiphertext.end());
    sigInput.insert(sigInput.end(), tagU.begin(), tagU.end());

    CryptoModule::Bytes sigma = CryptoModulePQC::Sign(sigKeyPair.privateKey, sigInput);

    // 9. 加密传输: tau = Enc(pkEnc, len(sigma) || sigma || ct)
    CryptoModule::Bytes plaintextToEnc;
    uint32_t sigLen = sigma.size();
    uint8_t lenBytes[4] = {
        static_cast<uint8_t>((sigLen >> 24) & 0xFF),
        static_cast<uint8_t>((sigLen >> 16) & 0xFF),
        static_cast<uint8_t>((sigLen >> 8) & 0xFF),
        static_cast<uint8_t>(sigLen & 0xFF)
    };
    plaintextToEnc.insert(plaintextToEnc.end(), lenBytes, lenBytes + 4);
    plaintextToEnc.insert(plaintextToEnc.end(), sigma.begin(), sigma.end());
    plaintextToEnc.insert(plaintextToEnc.end(), m_kemCiphertext.begin(), m_kemCiphertext.end());

    CryptoModule::Bytes tau = CryptoModulePQC::Encrypt(m_ask.pkEnc, plaintextToEnc);

    m_tau = tau;
    m_tagU = tagU;

    // 10. 返回响应
    ProtocolMessagesPQC::PQCAuthResponse resp;
    resp.uid = m_uid;
    resp.tau = tau;
    resp.tagU = tagU;
    return resp;
}

// ==========================================
// 步骤 5: 最终确认
// ==========================================
bool UserPQC::FinalizeAuthentication(const ProtocolMessagesPQC::PQCAuthConfirmation& confirmation) {
    if (!confirmation.success) return false;

    // 1. 验证服务器签名
    if (!CryptoModulePQC::VerifySignature(m_ask.serversigpk, confirmation.tagS, confirmation.serversigtag)) {
        throw std::runtime_error("[PQC] Server confirmation signature invalid!");
    }

    // 2. 本地计算期望的 tagS 以比对验证
    // 协议规范: tagS = H(sharedsecret || uid || tau || dhpubS || timestamp || nonce || tagU || "serverconfirm")
    CryptoModule::Bytes expectedTagSInput = m_sharedSecret;
    expectedTagSInput.insert(expectedTagSInput.end(), m_uid.begin(), m_uid.end());
    expectedTagSInput.insert(expectedTagSInput.end(), m_tau.begin(), m_tau.end());
    expectedTagSInput.insert(expectedTagSInput.end(), m_peerKEMPub.begin(), m_peerKEMPub.end()); 

    // --- 新增：大端序加入 timestamp ---
    for (int i = 7; i >= 0; --i) {
        expectedTagSInput.push_back(static_cast<uint8_t>((m_timestamp >> (i * 8)) & 0xFF));
    }
    // --- 新增：加入 nonce_S ---
    expectedTagSInput.insert(expectedTagSInput.end(), m_nonce.begin(), m_nonce.end());

    expectedTagSInput.insert(expectedTagSInput.end(), m_tagU.begin(), m_tagU.end());
    std::string serverConfirmStr = "serverconfirm";
    expectedTagSInput.insert(expectedTagSInput.end(), serverConfirmStr.begin(), serverConfirmStr.end());
    
    CryptoModule::Bytes expectedTagS = CryptoModule::Hash(expectedTagSInput);
    if (expectedTagS != confirmation.tagS) {
        throw std::runtime_error("[PQC] Server tagS mismatch! Bidirectional authentication failed.");
    }

    // 3. HKDF 双向密钥派生: salt = pk_KEM || ct
    CryptoModule::Bytes hkdfSalt = m_peerKEMPub;
    hkdfSalt.insert(hkdfSalt.end(), m_kemCiphertext.begin(), m_kemCiphertext.end());
    CryptoModule::Bytes prk = CryptoModulePQC::HKDF_Extract(hkdfSalt, m_sharedSecret);

    std::string c2sInfo = "c2s" + m_uid;
    std::string s2cInfo = "s2c" + m_uid;
    CryptoModule::Bytes c2sKey = CryptoModulePQC::HKDF_Expand(prk,
        CryptoModule::Bytes(c2sInfo.begin(), c2sInfo.end()), 32);
    CryptoModule::Bytes s2cKey = CryptoModulePQC::HKDF_Expand(prk,
        CryptoModule::Bytes(s2cInfo.begin(), s2cInfo.end()), 32);

    m_sessionKey = CryptoModulePQC::HKDF_Expand(prk,
        CryptoModule::Bytes({'s','e','s','s','i','o','n','k','e','y'}), 32);

    return true;
}
