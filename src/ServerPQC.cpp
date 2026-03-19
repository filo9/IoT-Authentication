#include "ServerPQC.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <openssl/rand.h>

extern void BroadcastToMonitorPQC(const std::string& event, const std::string& title, const std::string& details);

static std::string ToHexPQC(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ==========================================
// 构造、析构与数据库初始化
// ==========================================
ServerPQC::ServerPQC() {
    m_longTermKeys = CryptoModulePQC::GenerateSignatureKeyPair({});

    m_dbMasterKey.resize(32);
    if (RAND_bytes(m_dbMasterKey.data(), m_dbMasterKey.size()) != 1) {
        throw std::runtime_error("Failed to generate DB master key (PQC)");
    }
    InitDatabase();
}

ServerPQC::~ServerPQC() {
    if (m_db) sqlite3_close(m_db);
}

void ServerPQC::InitDatabase() {
    if (sqlite3_open("server_data_pqc.db", &m_db) != SQLITE_OK) {
        throw std::runtime_error("Can't open PQC database: " + std::string(sqlite3_errmsg(m_db)));
    }
    const char* sql = "CREATE TABLE IF NOT EXISTS users ("
                      "uid TEXT PRIMARY KEY NOT NULL, "
                      "pkSig BLOB NOT NULL, "
                      "skEnc BLOB NOT NULL);";
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::string err(errMsg);
        sqlite3_free(errMsg);
        throw std::runtime_error("SQL error (PQC): " + err);
    }
}

void ServerPQC::ClearDatabase() {
    const char* sql = "DELETE FROM users;";
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        sqlite3_free(errMsg);
        throw std::runtime_error("Failed to clear PQC database.");
    }
    m_activeSessions.clear();
    m_failureRecords.clear();
    m_perfMetrics = {};
    std::cout << "[ServerPQC] Database and sessions cleared.\n";
}

// ==========================================
// 数据库字段加密/解密 (与原协议完全一致)
// ==========================================
CryptoModule::Bytes ServerPQC::EncryptDBField(const CryptoModule::Bytes& plaintext) {
    CryptoModule::Bytes iv(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1)
        throw std::runtime_error("Failed to generate IV for PQC DB encryption");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context (PQC)");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, m_dbMasterKey.data(), iv.data());

    CryptoModule::Bytes ciphertext(plaintext.size() + 16);
    int len = 0, ct_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ct_len += len;
    ciphertext.resize(ct_len);

    CryptoModule::Bytes tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    CryptoModule::Bytes result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

CryptoModule::Bytes ServerPQC::DecryptDBField(const CryptoModule::Bytes& ciphertext) {
    if (ciphertext.size() < 28) throw std::runtime_error("PQC DB field ciphertext too short");

    CryptoModule::Bytes iv(ciphertext.begin(), ciphertext.begin() + 12);
    CryptoModule::Bytes tag(ciphertext.begin() + 12, ciphertext.begin() + 28);
    CryptoModule::Bytes encrypted(ciphertext.begin() + 28, ciphertext.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context (PQC)");

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, m_dbMasterKey.data(), iv.data());

    CryptoModule::Bytes plaintext(encrypted.size());
    int len = 0, pt_len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.data(), encrypted.size());
    pt_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("PQC DB field decryption failed");
    }
    pt_len += len;
    plaintext.resize(pt_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// ==========================================
// 注册阶段
// ==========================================
ProtocolMessagesPQC::RegistrationResponse ServerPQC::ProcessRegistration(
    const ProtocolMessagesPQC::RegistrationRequest& req)
{
    auto t_start = std::chrono::high_resolution_clock::now();

    // 检查重复注册
    const char* sql_check = "SELECT uid FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt_check;
    if (sqlite3_prepare_v2(m_db, sql_check, -1, &stmt_check, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt_check, 1, req.uid.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt_check) == SQLITE_ROW) {
            sqlite3_finalize(stmt_check);
            throw std::runtime_error("[PQC] UID [" + req.uid + "] already registered.");
        }
        sqlite3_finalize(stmt_check);
    }

    const char* sql_insert = "INSERT INTO users (uid, pkSig, skEnc) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql_insert, -1, &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare PQC insert statement");

    auto t_dbenc_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes encryptedSkEnc = EncryptDBField(req.avk_skEnc);
    auto t_dbenc_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.dbEncryptTime = std::chrono::duration<double, std::micro>(t_dbenc_end - t_dbenc_start).count();

    sqlite3_bind_text(stmt, 1, req.uid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, req.avk_pkSig.data(), req.avk_pkSig.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encryptedSkEnc.data(), encryptedSkEnc.size(), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert PQC user into database");
    }
    sqlite3_finalize(stmt);

    auto t_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.registrationTime = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    ProtocolMessagesPQC::RegistrationResponse resp;
    resp.success = true;
    resp.serversigpk = m_longTermKeys.publicKey;
    return resp;
}

// ==========================================
// 步骤 2: 生成后量子挑战 — ML-KEM 替代 ECDH
// ==========================================
ProtocolMessagesPQC::PQCAuthChallenge ServerPQC::GenerateAuthChallenge(const std::string& uid) {
    auto t_challenge_start = std::chrono::high_resolution_clock::now();

    // 验证用户存在
    const char* sql = "SELECT uid FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, uid.c_str(), -1, SQLITE_TRANSIENT);
    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    if (!exists) throw std::runtime_error("[PQC] User not found: " + uid);

    PQCAuthSession session;

    // 生成 ML-KEM-768 临时密钥对 (替代 DH 密钥对)
    auto t_kem_start = std::chrono::high_resolution_clock::now();
    session.tempKEM = CryptoModulePQC::KEM_KeyGen();
    auto t_kem_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.kemKeyGenTime = std::chrono::duration<double, std::micro>(t_kem_end - t_kem_start).count();

    // 时间戳
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t timestamp = static_cast<uint64_t>(ms);

    // 随机 nonce
    CryptoModule::Bytes nonce(16);
    RAND_bytes(nonce.data(), nonce.size());
    session.timestamp = timestamp;
    session.nonce = nonce;
    // 签名: Sign(sk_server, pk_KEM)  — 注意这里签的是 pk_KEM 而非 dhpubS
    auto t_sign_start = std::chrono::high_resolution_clock::now();
    session.serversigm = CryptoModulePQC::Sign(m_longTermKeys.privateKey, session.tempKEM.publicKey);
    auto t_sign_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.signTime = std::chrono::duration<double, std::micro>(t_sign_end - t_sign_start).count();

    m_activeSessions[uid] = std::move(session);

    auto t_challenge_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.challengeGenTime = std::chrono::duration<double, std::milli>(t_challenge_end - t_challenge_start).count();

    ProtocolMessagesPQC::PQCAuthChallenge challenge;
    challenge.pkKEM = m_activeSessions[uid].tempKEM.publicKey;
    challenge.serversigm = m_activeSessions[uid].serversigm;
    challenge.timestamp = timestamp;
    challenge.nonce = nonce;
    return challenge;
}

// ==========================================
// 步骤 4: 处理客户端响应 — ML-KEM.Decaps 替代 DH 协商
// ==========================================
ProtocolMessagesPQC::PQCAuthConfirmation ServerPQC::ProcessAuthResponse(
    const ProtocolMessagesPQC::PQCAuthResponse& resp)
{
    auto t_auth_start = std::chrono::high_resolution_clock::now();
    m_perfMetrics.totalAuthCount++;

    ProtocolMessagesPQC::PQCAuthConfirmation confirmation;
    confirmation.success = false;

    // 检查账户锁定
    time_t now = time(nullptr);
    auto failIt = m_failureRecords.find(resp.uid);
    if (failIt != m_failureRecords.end()) {
        if (now < failIt->second.lockUntil) {
            int remaining = failIt->second.lockUntil - now;
            std::string msg = "[PQC] Account locked. Retry in " + std::to_string(remaining) + "s.";
            BroadcastToMonitorPQC("error", "Account Locked", msg);
            throw std::runtime_error(msg);
        }
    }

    // 查询数据库
    const char* sql = "SELECT pkSig, skEnc FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("PQC database read error");
    sqlite3_bind_text(stmt, 1, resp.uid.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return confirmation;
    }

    const uint8_t* pkSigBlob = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
    CryptoModule::Bytes db_pkSig(pkSigBlob, pkSigBlob + sqlite3_column_bytes(stmt, 0));
    const uint8_t* skEncBlob = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 1));
    CryptoModule::Bytes encryptedSkEnc(skEncBlob, skEncBlob + sqlite3_column_bytes(stmt, 1));
    sqlite3_finalize(stmt);

    // 解密 skEnc
    auto t_dbdec_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes db_skEnc = DecryptDBField(encryptedSkEnc);
    auto t_dbdec_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.dbDecryptTime = std::chrono::duration<double, std::micro>(t_dbdec_end - t_dbdec_start).count();

    auto sessionIt = m_activeSessions.find(resp.uid);
    if (sessionIt == m_activeSessions.end()) return confirmation;
    PQCAuthSession& session = sessionIt->second;

    std::string auditMsg1 = "【密文包裹 tau】:\n" + ToHexPQC(resp.tau).substr(0, 64) + "...\n\n";
    auditMsg1 += "【确认标签 tagU】:\n" + ToHexPQC(resp.tagU) + "\n\n";
    auditMsg1 += "⚠️ 准备使用数据库存储的 sk_Enc 解密 tau。";
    BroadcastToMonitorPQC("warning", "📥 1. [PQC] 收到终端认证挑战响应", auditMsg1);

    // 解密 tau: (sigma, ct) <- Dec(skEnc, tau)
    auto t_dec_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes decrypted = CryptoModulePQC::Decrypt(db_skEnc, resp.tau);
    auto t_dec_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.decryptTime = std::chrono::duration<double, std::micro>(t_dec_end - t_dec_start).count();

    // 解析: [4字节sigma长度] || [sigma] || [ct]
    if (decrypted.size() < 4) throw std::runtime_error("[PQC] Decrypted tau too short");
    uint32_t sigLen = (static_cast<uint32_t>(decrypted[0]) << 24) |
                      (static_cast<uint32_t>(decrypted[1]) << 16) |
                      (static_cast<uint32_t>(decrypted[2]) << 8) |
                       static_cast<uint32_t>(decrypted[3]);

    if (decrypted.size() < 4 + sigLen) throw std::runtime_error("[PQC] Invalid tau format");
    CryptoModule::Bytes sigma(decrypted.begin() + 4, decrypted.begin() + 4 + sigLen);
    CryptoModule::Bytes ct(decrypted.begin() + 4 + sigLen, decrypted.end());

    std::string auditMsg2 = "✅ AEAD 解密成功 (验证终端加密密钥合法)！\n\n";
    auditMsg2 += "【提取出 KEM 密文 ct】:\n" + ToHexPQC(ct).substr(0, 64) + "...\n\n";
    auditMsg2 += "【提取出终端 ECDSA 签名 sigma】:\n" + ToHexPQC(sigma).substr(0, 64) + "...";
    BroadcastToMonitorPQC("success", "🔓 2. [PQC] tau 解密与数据分离", auditMsg2);
    // 验证用户签名: Verify(pkSig, (uid, pk_KEM, ct, tagU), sigma)
    CryptoModule::Bytes sigData(resp.uid.begin(), resp.uid.end());
    sigData.insert(sigData.end(), session.tempKEM.publicKey.begin(), session.tempKEM.publicKey.end());
    sigData.insert(sigData.end(), ct.begin(), ct.end());
    sigData.insert(sigData.end(), resp.tagU.begin(), resp.tagU.end());

    auto t_verify_start = std::chrono::high_resolution_clock::now();
    bool sigValid = CryptoModulePQC::VerifySignature(db_pkSig, sigData, sigma);
    auto t_verify_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.verifyTime = std::chrono::duration<double, std::micro>(t_verify_end - t_verify_start).count();

    if (!sigValid) {
        m_perfMetrics.failedAuthCount++;
        BroadcastToMonitorPQC("error", "PQC Signature Invalid", "User signature verification failed for " + resp.uid);
        throw std::runtime_error("[PQC] User signature verification failed!");
    }

    std::string auditMsg3 = "签名原文公式: uid || pk_KEM || ct || tagU\n\n";
    auditMsg3 += "💡 网关并不拥有用户私钥，而是提取注册时绑定的公钥进行非对称验签。\n\n";
    auditMsg3 += "【使用的验证公钥 pk_Sig】:\n" + ToHexPQC(db_pkSig).substr(0, 64) + "...";
    BroadcastToMonitorPQC("success", "✍️ 3. [PQC] 终端 ECDSA 签名验证通过", auditMsg3);
    // ML-KEM 解封装: shared_secret <- Decaps(sk_KEM, ct)
    auto t_decaps_start = std::chrono::high_resolution_clock::now();
    session.sharedSecret = CryptoModulePQC::KEM_Decaps(session.tempKEM.secretKey, ct);
    auto t_decaps_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.kemDecapsTime = std::chrono::duration<double, std::micro>(t_decaps_end - t_decaps_start).count();

    BroadcastToMonitorPQC("crypto", "🔑 4. [PQC] 执行 ML-KEM 解封装", "公式: KEM.Decaps(网关临时私钥 sk_KEM, 终端密文 ct)\n\n【恢复出的 SharedSecret】:\n" + ToHexPQC(session.sharedSecret));
    // 验证 tagU = H(shared_secret || uid || pk_KEM || timestamp || nonce_S || server_sigm || ct || "clientconfirm")
    CryptoModule::Bytes tagInput = session.sharedSecret;
    tagInput.insert(tagInput.end(), resp.uid.begin(), resp.uid.end());
    tagInput.insert(tagInput.end(), session.tempKEM.publicKey.begin(), session.tempKEM.publicKey.end());

    // 大端序加入 timestamp
    for (int i = 7; i >= 0; --i) {
        tagInput.push_back(static_cast<uint8_t>((session.timestamp >> (i * 8)) & 0xFF));
    }
    // 加入 nonce_S
    tagInput.insert(tagInput.end(), session.nonce.begin(), session.nonce.end());

    tagInput.insert(tagInput.end(), session.serversigm.begin(), session.serversigm.end());
    tagInput.insert(tagInput.end(), ct.begin(), ct.end());
    std::string confirmStr = "clientconfirm";
    tagInput.insert(tagInput.end(), confirmStr.begin(), confirmStr.end());

    CryptoModule::Bytes expectedTagU = CryptoModulePQC::Hash(tagInput);
    if (expectedTagU != resp.tagU) {
        m_perfMetrics.failedAuthCount++;
        BroadcastToMonitorPQC("error", "PQC TagU Mismatch", "Client confirmation tag verification failed");
        throw std::runtime_error("[PQC] tagU verification failed!");
    }
    std::string auditMsg4 = "tagU 组成部分:\n";
    auditMsg4 += "1. SharedSecret: " + ToHexPQC(session.sharedSecret).substr(0, 16) + "...\n";
    auditMsg4 += "2. uid: " + resp.uid + "\n";
    auditMsg4 += "3. pk_KEM: " + ToHexPQC(session.tempKEM.publicKey).substr(0, 16) + "...\n";
    auditMsg4 += "4. timestamp: " + std::to_string(session.timestamp) + "\n";
    auditMsg4 += "5. nonce_S: " + ToHexPQC(session.nonce) + "\n";
    auditMsg4 += "6. serversigm: " + ToHexPQC(session.serversigm).substr(0, 16) + "...\n";
    auditMsg4 += "7. ct: " + ToHexPQC(ct).substr(0, 16) + "...\n";
    auditMsg4 += "8. 常量: 'clientconfirm'\n\n";
    auditMsg4 += "网关本地计算出的 tagU:\n" + ToHexPQC(expectedTagU) + "\n\n";
    auditMsg4 += "✅ 比对结果：与终端上传的 tagU 完美匹配！";
    BroadcastToMonitorPQC("success", "✅ 5. [PQC] 终端确认标签 tagU 匹配通过", auditMsg4);
    // HKDF 双向密钥派生: salt = pk_KEM || ct (替代 dhpubS || dhpubU)
    auto t_hkdf_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes hkdfSalt = session.tempKEM.publicKey;
    hkdfSalt.insert(hkdfSalt.end(), ct.begin(), ct.end());
    CryptoModule::Bytes prk = CryptoModulePQC::HKDF_Extract(hkdfSalt, session.sharedSecret);

    std::string c2sInfo = "c2s" + resp.uid;
    std::string s2cInfo = "s2c" + resp.uid;
    CryptoModule::Bytes c2sKey = CryptoModulePQC::HKDF_Expand(prk,
        CryptoModule::Bytes(c2sInfo.begin(), c2sInfo.end()), 32);
    CryptoModule::Bytes s2cKey = CryptoModulePQC::HKDF_Expand(prk,
        CryptoModule::Bytes(s2cInfo.begin(), s2cInfo.end()), 32);

    session.sessionKey = CryptoModulePQC::HKDF_Expand(prk,
        CryptoModule::Bytes({'s','e','s','s','i','o','n','k','e','y'}), 32);
    auto t_hkdf_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.hkdfTime = std::chrono::duration<double, std::micro>(t_hkdf_end - t_hkdf_start).count();

    // 初始化安全记录层
    session.secureLayer.Initialize(s2cKey, c2sKey);

    // 生成 tagS = H(shared_secret || uid || tau || pk_KEM || timestamp || nonce || tagU || "serverconfirm")
    CryptoModule::Bytes tagSInput = session.sharedSecret;
    tagSInput.insert(tagSInput.end(), resp.uid.begin(), resp.uid.end());
    tagSInput.insert(tagSInput.end(), resp.tau.begin(), resp.tau.end());
    tagSInput.insert(tagSInput.end(), session.tempKEM.publicKey.begin(), session.tempKEM.publicKey.end());

    // --- 新增：大端序加入 timestamp ---
    for (int i = 7; i >= 0; --i) {
        tagSInput.push_back(static_cast<uint8_t>((session.timestamp >> (i * 8)) & 0xFF));
    }
    // --- 新增：加入 nonce_S ---
    tagSInput.insert(tagSInput.end(), session.nonce.begin(), session.nonce.end());

    tagSInput.insert(tagSInput.end(), resp.tagU.begin(), resp.tagU.end());
    std::string serverConfirmStr = "serverconfirm";
    tagSInput.insert(tagSInput.end(), serverConfirmStr.begin(), serverConfirmStr.end());

    CryptoModule::Bytes tagS = CryptoModulePQC::Hash(tagSInput);

    // 服务器签名 tagS
    auto t_sign2_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes serversigtag = CryptoModulePQC::Sign(m_longTermKeys.privateKey, tagS);
    auto t_sign2_end = std::chrono::high_resolution_clock::now();

    m_perfMetrics.successAuthCount++;
    auto t_auth_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.authVerifyTime = std::chrono::duration<double, std::milli>(t_auth_end - t_auth_start).count();
    m_perfMetrics.totalAuthTime = m_perfMetrics.challengeGenTime + m_perfMetrics.authVerifyTime;

    confirmation.success = true;
    confirmation.tagS = tagS;
    confirmation.serversigtag = serversigtag;
    std::string auditMsg5 = "tagS 组成部分:\n";
    auditMsg5 += "1. SharedSecret: " + ToHexPQC(session.sharedSecret).substr(0, 16) + "...\n";
    auditMsg5 += "2. uid: " + resp.uid + "\n";
    auditMsg5 += "3. tau (密文): " + ToHexPQC(resp.tau).substr(0, 16) + "...\n";
    auditMsg5 += "4. pk_KEM: " + ToHexPQC(session.tempKEM.publicKey).substr(0, 16) + "...\n";
    auditMsg5 += "5. timestamp: " + std::to_string(session.timestamp) + "\n";
    auditMsg5 += "6. nonce_S: " + ToHexPQC(session.nonce) + "\n";
    auditMsg5 += "7. tagU: " + ToHexPQC(resp.tagU).substr(0, 16) + "...\n";
    auditMsg5 += "8. 常量: 'serverconfirm'\n\n";
    auditMsg5 += "【生成网关确认标签 tagS】:\n" + ToHexPQC(tagS) + "\n\n";
    auditMsg5 += "【网关最终签名 serversigtag】:\n" + ToHexPQC(serversigtag).substr(0, 64) + "...";
    BroadcastToMonitorPQC("crypto", "🏷️ 6. [PQC] 签发网关反向确认参数", auditMsg5);
    BroadcastToMonitorPQC("success", "PQC Auth Success",
        "ML-KEM-768 mutual authentication completed for " + resp.uid +
        "\nKEM KeyGen: " + std::to_string(m_perfMetrics.kemKeyGenTime) + " us" +
        "\nKEM Decaps: " + std::to_string(m_perfMetrics.kemDecapsTime) + " us");

    return confirmation;
}

// ==========================================
// 辅助方法
// ==========================================
CryptoModule::Bytes ServerPQC::GetSessionKey(const std::string& uid) const {
    auto it = m_activeSessions.find(uid);
    if (it == m_activeSessions.end()) throw std::runtime_error("[PQC] No session for " + uid);
    return it->second.sessionKey;
}

void ServerPQC::HandleAuthFailure(const std::string& uid) {
    auto& record = m_failureRecords[uid];
    record.failCount++;
    record.lastFailTime = time(nullptr);

    // 指数退避: 2^failCount 秒，最大 300 秒
    int lockDuration = std::min(1 << record.failCount, 300);
    record.lockUntil = record.lastFailTime + lockDuration;

    m_perfMetrics.failedAuthCount++;
    BroadcastToMonitorPQC("error", "PQC Auth Failure",
        "UID: " + uid + ", failures: " + std::to_string(record.failCount) +
        ", locked for " + std::to_string(lockDuration) + "s");
}

PQCPerformanceMetrics ServerPQC::GetPerformanceMetrics() const {
    return m_perfMetrics;
}

void ServerPQC::ExportPerformanceReport(const std::string& filepath) const {
    std::ofstream ofs(filepath);
    if (!ofs.is_open()) throw std::runtime_error("Cannot open file: " + filepath);

    ofs << "Metric,Value,Unit\n";
    ofs << "ML-KEM KeyGen," << m_perfMetrics.kemKeyGenTime << ",us\n";
    ofs << "ML-KEM Encaps," << m_perfMetrics.kemEncapsTime << ",us\n";
    ofs << "ML-KEM Decaps," << m_perfMetrics.kemDecapsTime << ",us\n";
    ofs << "ECDSA Sign," << m_perfMetrics.signTime << ",us\n";
    ofs << "ECDSA Verify," << m_perfMetrics.verifyTime << ",us\n";
    ofs << "ECIES Encrypt," << m_perfMetrics.encryptTime << ",us\n";
    ofs << "ECIES Decrypt," << m_perfMetrics.decryptTime << ",us\n";
    ofs << "HKDF Derivation," << m_perfMetrics.hkdfTime << ",us\n";
    ofs << "DB Field Encrypt," << m_perfMetrics.dbEncryptTime << ",us\n";
    ofs << "DB Field Decrypt," << m_perfMetrics.dbDecryptTime << ",us\n";
    ofs << "Registration Phase," << m_perfMetrics.registrationTime << ",ms\n";
    ofs << "Challenge Generation," << m_perfMetrics.challengeGenTime << ",ms\n";
    ofs << "Auth Verification," << m_perfMetrics.authVerifyTime << ",ms\n";
    ofs << "Total Auth Time," << m_perfMetrics.totalAuthTime << ",ms\n";
    ofs << "Total Auth Attempts," << m_perfMetrics.totalAuthCount << ",count\n";
    ofs << "Successful Auths," << m_perfMetrics.successAuthCount << ",count\n";
    ofs << "Failed Auths," << m_perfMetrics.failedAuthCount << ",count\n";

    double rate = m_perfMetrics.totalAuthCount > 0
        ? (100.0 * m_perfMetrics.successAuthCount / m_perfMetrics.totalAuthCount) : 0.0;
    ofs << "Success Rate," << rate << ",%\n";
    ofs << "KEM Public Key Size," << m_perfMetrics.kemPublicKeySize << ",bytes\n";
    ofs << "KEM Ciphertext Size," << m_perfMetrics.kemCiphertextSize << ",bytes\n";
    ofs << "KEM Shared Secret Size," << m_perfMetrics.kemSharedSecretSize << ",bytes\n";

    ofs.close();
    std::cout << "[ServerPQC] Performance report exported to " << filepath << "\n";
}
