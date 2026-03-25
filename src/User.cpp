#include "User.h"
#include "DeterministicECC.h"
#include "SecureBytes.h"
#include <openssl/crypto.h>
#include <stdexcept>
#include <iostream>
#include <chrono>

// ==========================================
// 注册阶段
// ==========================================

ProtocolMessages::RegistrationRequest User::GenerateRegistrationRequest(
    const std::string& password, 
    const CryptoModule::Bytes& biometric) 
{
    // 1. 生物特征处理: R, P <- FuzzyExtractor.Gen(bio) 
    auto feData = BioModule::Gen(biometric);

    // 2. 设备密钥派生: K <- TEEKeyModule.Enroll(deviceUID)
    // 使用 PBKDF2(deviceUID, random_salt) 模拟 TEE/TPM 硬件绑定设备密钥
    std::string keystore_file = "user_" + m_uid + "_keystore.dat";
    SecureBytes deviceKey = TEEKeyModule::Enroll(m_uid, keystore_file);

    // 3. 主密钥派生: kmaster = HMAC-SHA256(K, pw || R) [cite: 157]
    CryptoModule::Bytes pwBytes(password.begin(), password.end());
    SecureBytes kmaster = TEEKeyModule::ComputeMasterKey(deviceKey, pwBytes, feData.R);

    // 4. 使用新接口：基于 K_master 确定性生成用户签名密钥对
    auto sigKeyPair = DeterministicECC::DeriveKeyPairFromSeed(kmaster);
    // 注册完成后立即安全擦除私钥（服务器只需要公钥）
    struct SigKeyGuard {
        CryptoModule::KeyPair& kp;
        ~SigKeyGuard() { OPENSSL_cleanse(kp.privateKey.data(), kp.privateKey.size()); }
    } sigGuard{sigKeyPair};

    // 5. 生成加密密钥对 [cite: 159]
    auto encKeyPair = CryptoModule::GenerateEncryptionKeyPair();

    // 6. 保存本地凭证 ask (此时还缺服务器公钥，等响应回来补齐) [cite: 169]
    m_ask.P = feData.P;
    m_ask.pkEnc = encKeyPair.publicKey;

    // 7. 构造发给服务器的注册包: avk = (pk_Sig, sk_Enc) [cite: 161]
    ProtocolMessages::RegistrationRequest req;
    req.uid = m_uid;
    req.avk_pkSig = sigKeyPair.publicKey;
    req.avk_skEnc = encKeyPair.privateKey; // 将解密私钥托管给服务器 [cite: 160]

    return req;
}

void User::ProcessRegistrationResponse(const ProtocolMessages::RegistrationResponse& response) {
    if (!response.success) throw std::runtime_error("Registration failed on server.");
    // 补齐本地凭证 [cite: 169]
    m_ask.serversigpk = response.serversigpk; 
}

// ==========================================
// 认证与密钥协商阶段
// ==========================================

ProtocolMessages::AuthRequest User::InitiateAuthentication() {
    ProtocolMessages::AuthRequest req;
    req.uid = m_uid; // [cite: 174]
    return req;
}

ProtocolMessages::AuthResponse User::ProcessAuthChallenge(
    const ProtocolMessages::AuthChallenge& challenge,
    const std::string& password,
    const CryptoModule::Bytes& currentBiometric)
{
    // 1. 验证时间戳新鲜性（30 秒窗口）
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t currentTime = static_cast<uint64_t>(ms);

    const uint64_t TIME_WINDOW_MS = 30000; // 30 秒
    if (currentTime < challenge.timestamp || currentTime - challenge.timestamp > TIME_WINDOW_MS) {
        throw std::runtime_error("Challenge timestamp expired or invalid! Possible replay attack.");
    }

    // 2. 验证服务器签名（签名内容：dhpubS || timestamp || nonce）
    CryptoModule::Bytes sigInput = challenge.dhpubS;
    // 将 timestamp 按大端序序列化为 8 字节
    for (int i = 7; i >= 0; --i) {
        sigInput.push_back(static_cast<uint8_t>((challenge.timestamp >> (i * 8)) & 0xFF));
    }
    sigInput.insert(sigInput.end(), challenge.nonce.begin(), challenge.nonce.end());

    if (!CryptoModule::VerifySignature(m_ask.serversigpk, sigInput, challenge.serversigm)) {
        throw std::runtime_error("Server signature verification failed! Possible MITM attack.");
    }
    
    // 保存上下文供后续生成 Tag 使用
    m_peerDHPub = challenge.dhpubS;
    m_serverSigM = challenge.serversigm;
    m_timestamp = challenge.timestamp;
    m_nonce = challenge.nonce;
    // 2. 恢复生物特征 R <- FuzzyExtractor.Rep(bio', P) [cite: 182]
    CryptoModule::Bytes R = BioModule::Rep(currentBiometric, m_ask.P);
    if (R.empty()) {
        throw std::runtime_error("Biometric mismatch! Authentication aborted.");
    }

    // 3. 重新派生设备密钥 K 并计算主密钥 kmaster [cite: 183]
    std::string keystore_file = "user_" + m_uid + "_keystore.dat";
    SecureBytes deviceKey = TEEKeyModule::Derive(m_uid, keystore_file);

    // 然后再进行 kmaster 的计算：
    CryptoModule::Bytes pwBytes(password.begin(), password.end());
    SecureBytes kmaster = TEEKeyModule::ComputeMasterKey(deviceKey, pwBytes, R);

    // 4. 真正通过 kmaster 确定性重构签名密钥对！(无私钥存储落地)
    auto sigKeyPair = DeterministicECC::DeriveKeyPairFromSeed(kmaster);
    // 签名密钥对使用完立即安全擦除私钥
    struct SigKeyGuard {
        CryptoModule::KeyPair& kp;
        ~SigKeyGuard() { OPENSSL_cleanse(kp.privateKey.data(), kp.privateKey.size()); }
    } sigGuard{sigKeyPair};

    // 5. 生成临时 DH 密钥，计算共享秘密 [cite: 185-186]
    m_tempDH = CryptoModule::GenerateDHKeyPair();
    m_sharedSecret = CryptoModule::ComputeSharedSecret(m_tempDH.privateKey, challenge.dhpubS);

    /// 6. 生成用户确认标签 
    // 公式: tagU = H(sharedsecret || uid || dhpubS || timestamp || nonce_S || serversigm || dhpubU || "clientconfirm")
    CryptoModule::Bytes tagInput = m_sharedSecret;
    tagInput.insert(tagInput.end(), m_uid.begin(), m_uid.end());
    tagInput.insert(tagInput.end(), challenge.dhpubS.begin(), challenge.dhpubS.end());
    
    // 将 timestamp 按大端序序列化为 8 字节加入
    for (int i = 7; i >= 0; --i) {
        tagInput.push_back(static_cast<uint8_t>((challenge.timestamp >> (i * 8)) & 0xFF));
    }
    // 加入服务器发来的 nonce_S
    tagInput.insert(tagInput.end(), challenge.nonce.begin(), challenge.nonce.end());
    
    tagInput.insert(tagInput.end(), challenge.serversigm.begin(), challenge.serversigm.end());
    tagInput.insert(tagInput.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());
    std::string confirmStr = "clientconfirm";
    tagInput.insert(tagInput.end(), confirmStr.begin(), confirmStr.end());
    
    CryptoModule::Bytes tagU = CryptoModule::Hash(tagInput);
    

    // 7. 用户签名 sigma = Sign(skSig, uid || dhpubS || dhpubU || tagU) [cite: 188]
    CryptoModule::Bytes sigInput2(m_uid.begin(), m_uid.end());
    sigInput2.insert(sigInput2.end(), challenge.dhpubS.begin(), challenge.dhpubS.end());
    sigInput2.insert(sigInput2.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());
    sigInput2.insert(sigInput2.end(), tagU.begin(), tagU.end());

    // 使用当场算出的私钥进行签名
    CryptoModule::Bytes sigma = CryptoModule::Sign(sigKeyPair.privateKey, sigInput2);
    // 8. 加密传输 tau = Enc(pkEnc, len(sigma) || sigma || dhpubU)
    CryptoModule::Bytes plaintextToEnc;
    uint32_t sigLen = sigma.size();
    
    // 手动将 32位长度 按大端序转为 4 个字节的前缀
    uint8_t lenBytes[4] = {
        static_cast<uint8_t>((sigLen >> 24) & 0xFF),
        static_cast<uint8_t>((sigLen >> 16) & 0xFF),
        static_cast<uint8_t>((sigLen >> 8) & 0xFF),
        static_cast<uint8_t>(sigLen & 0xFF)
    };
    
    // 组装格式: [4字节签名长度] || [签名内容] || [DH公钥]
    plaintextToEnc.insert(plaintextToEnc.end(), lenBytes, lenBytes + 4);
    plaintextToEnc.insert(plaintextToEnc.end(), sigma.begin(), sigma.end());
    plaintextToEnc.insert(plaintextToEnc.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());
    
    CryptoModule::Bytes tau = CryptoModule::Encrypt(m_ask.pkEnc, plaintextToEnc);

    m_tau = tau;
    m_tagU = tagU;

    // 9. 返回响应 [cite: 191]
    ProtocolMessages::AuthResponse resp;
    resp.uid = m_uid;
    resp.tau = tau;
    resp.tagU = tagU;

    return resp;
}

bool User::FinalizeAuthentication(const ProtocolMessages::AuthConfirmation& confirmation) {
    if (!confirmation.success) return false;

    // 1. 验证服务器端发来的确认标签签名 (防止中间人篡改 tagS)
    if (!CryptoModule::VerifySignature(m_ask.serversigpk, confirmation.tagS, confirmation.serversigtag)) {
        throw std::runtime_error("Server confirmation signature invalid! Protocol aborted.");
    }

    // 2. 本地计算期望的 tagS 以比对验证
    // 协议规范: tagS = H(sharedsecret || uid || tau || dhpubS || timestamp || nonce || tagU || "serverconfirm")
    CryptoModule::Bytes expectedTagSInput = m_sharedSecret;
    expectedTagSInput.insert(expectedTagSInput.end(), m_uid.begin(), m_uid.end());
    expectedTagSInput.insert(expectedTagSInput.end(), m_tau.begin(), m_tau.end());
    expectedTagSInput.insert(expectedTagSInput.end(), m_peerDHPub.begin(), m_peerDHPub.end()); 

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

    // 比对本地计算出的 tagS 与服务器发来的 tagS 是否完全一致
    if (expectedTagS != confirmation.tagS) {
        throw std::runtime_error("Server tagS mismatch! Bidirectional authentication failed.");
    }

    // 3. 派生最终会话密钥（使用 HKDF 两阶段密钥派生 + 双向密钥分离）
    // Extract: PRK = HKDF-Extract(salt=dhpubS||dhpubU, IKM=sharedSecret)
    CryptoModule::Bytes hkdfSalt = m_peerDHPub;
    hkdfSalt.insert(hkdfSalt.end(), m_tempDH.publicKey.begin(), m_tempDH.publicKey.end());
    CryptoModule::Bytes prk = CryptoModule::HKDF_Extract(hkdfSalt, m_sharedSecret);

    // Expand: 从同一 PRK 派生双向独立密钥
    std::string c2sInfo = "c2s_" + m_uid;
    std::string s2cInfo = "s2c_" + m_uid;
    CryptoModule::Bytes c2sKey = CryptoModule::HKDF_Expand(prk,
        CryptoModule::Bytes(c2sInfo.begin(), c2sInfo.end()), 32);
    CryptoModule::Bytes s2cKey = CryptoModule::HKDF_Expand(prk,
        CryptoModule::Bytes(s2cInfo.begin(), s2cInfo.end()), 32);

    // 客户端：发送用 c2s_key，接收用 s2c_key
    m_sessionKey = CryptoModule::HKDF_Expand(prk,
        CryptoModule::Bytes({'s','e','s','s','i','o','n','k','e','y'}), 32);

    return true; // 双向认证彻底成功！
}