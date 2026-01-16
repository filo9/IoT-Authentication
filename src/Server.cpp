#include "Server.h"
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <chrono>
#include <openssl/rand.h>
#include <cmath>

// ==========================================
// 【新增】：引入 main_server.cpp 中的广播功能与 Hex 转换工具
// ==========================================
extern void BroadcastToMonitor(const std::string& event, const std::string& title, const std::string& details);

static std::string ToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ==========================================
// 构造、析构与数据库初始化
// ==========================================
Server::Server() {
    m_longTermKeys = CryptoModule::GenerateSignatureKeyPair({});

    // 生成数据库主密钥（32 字节）
    // 生产环境应从环境变量或 HSM 加载，这里演示用随机生成
    m_dbMasterKey.resize(32);
    if (RAND_bytes(m_dbMasterKey.data(), m_dbMasterKey.size()) != 1) {
        throw std::runtime_error("Failed to generate DB master key");
    }

    InitDatabase();
}

Server::~Server() {
    if (m_db) sqlite3_close(m_db);
}

void Server::InitDatabase() {
    if (sqlite3_open("server_data.db", &m_db) != SQLITE_OK) {
        throw std::runtime_error("Can't open database: " + std::string(sqlite3_errmsg(m_db)));
    }
    const char* sql_create_table = 
        "CREATE TABLE IF NOT EXISTS users ("
        "uid TEXT PRIMARY KEY NOT NULL, "
        "pkSig BLOB NOT NULL, "
        "skEnc BLOB NOT NULL);";
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql_create_table, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::string errStr(errMsg);
        sqlite3_free(errMsg);
        throw std::runtime_error("SQL error on creating table: " + errStr);
    }
}

void Server::ClearDatabase() {
    const char* sql_clear = "DELETE FROM users;";
    char* errMsg = nullptr;
    if (sqlite3_exec(m_db, sql_clear, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        sqlite3_free(errMsg);
        throw std::runtime_error("Failed to clear database.");
    }
    m_activeSessions.clear();
    m_failureRecords.clear(); // 清空失败记录
    m_perfMetrics = {};
    std::cout << "[Server] Database and active sessions cleared successfully.\n";
}

// ==========================================
// 数据库字段加密/解密（保护 skEnc）
// ==========================================
CryptoModule::Bytes Server::EncryptDBField(const CryptoModule::Bytes& plaintext) {
    // 使用 AES-256-GCM 加密
    // 格式: [IV(12)] || [Tag(16)] || [Ciphertext]

    CryptoModule::Bytes iv(12);
    if (RAND_bytes(iv.data(), iv.size()) != 1) {
        throw std::runtime_error("Failed to generate IV for DB encryption");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, m_dbMasterKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init AES-256-GCM for DB encryption");
    }

    CryptoModule::Bytes ciphertext(plaintext.size() + 16);
    int len = 0, ciphertext_len = 0;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    CryptoModule::Bytes tag(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);

    // 组装: IV || Tag || Ciphertext
    CryptoModule::Bytes result;
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), tag.begin(), tag.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    return result;
}

CryptoModule::Bytes Server::DecryptDBField(const CryptoModule::Bytes& ciphertext) {
    // 解析: [IV(12)] || [Tag(16)] || [Ciphertext]
    if (ciphertext.size() < 28) throw std::runtime_error("DB field ciphertext too short");

    CryptoModule::Bytes iv(ciphertext.begin(), ciphertext.begin() + 12);
    CryptoModule::Bytes tag(ciphertext.begin() + 12, ciphertext.begin() + 28);
    CryptoModule::Bytes encrypted(ciphertext.begin() + 28, ciphertext.end());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, m_dbMasterKey.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init AES-256-GCM for DB decryption");
    }

    CryptoModule::Bytes plaintext(encrypted.size());
    int len = 0, plaintext_len = 0;
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted.data(), encrypted.size());
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DB field decryption failed or tag verification failed");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

// ==========================================
// 注册阶段
// ==========================================
ProtocolMessages::RegistrationResponse Server::ProcessRegistration(
    const ProtocolMessages::RegistrationRequest& req)
{
    auto t_reg_start = std::chrono::high_resolution_clock::now();

    const char* sql_check = "SELECT uid FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt_check;
    if (sqlite3_prepare_v2(m_db, sql_check, -1, &stmt_check, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt_check, 1, req.uid.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt_check) == SQLITE_ROW) {
            sqlite3_finalize(stmt_check);
            throw std::runtime_error("UID [" + req.uid + "] 已被注册！每个设备只能注册一次。");
        }
        sqlite3_finalize(stmt_check);
    }

    const char* sql_insert = "INSERT INTO users (uid, pkSig, skEnc) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql_insert, -1, &stmt, nullptr) != SQLITE_OK) throw std::runtime_error("Failed to prepare insert statement");

    // 加密 skEnc 字段后再存入数据库
    auto t_dbenc_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes encryptedSkEnc = EncryptDBField(req.avk_skEnc);
    auto t_dbenc_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.dbEncryptTime = std::chrono::duration<double, std::micro>(t_dbenc_end - t_dbenc_start).count();

    sqlite3_bind_text(stmt, 1, req.uid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 2, req.avk_pkSig.data(), req.avk_pkSig.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(stmt, 3, encryptedSkEnc.data(), encryptedSkEnc.size(), SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to insert user into database");
    }
    sqlite3_finalize(stmt);

    auto t_reg_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.registrationTime = std::chrono::duration<double, std::milli>(t_reg_end - t_reg_start).count();

    ProtocolMessages::RegistrationResponse resp;
    resp.success = true;
    resp.serversigpk = m_longTermKeys.publicKey;
    return resp;
}

// ==========================================
// 认证与密钥协商阶段
// ==========================================
ProtocolMessages::AuthChallenge Server::GenerateAuthChallenge(const std::string& uid) {
    auto t_challenge_start = std::chrono::high_resolution_clock::now();

    const char* sql_select = "SELECT uid FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(m_db, sql_select, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, uid.c_str(), -1, SQLITE_TRANSIENT);

    bool userExists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    if (!userExists) throw std::runtime_error("User not found in real database.");

    AuthSession session;
    auto t_dh_start = std::chrono::high_resolution_clock::now();
    session.tempDH = CryptoModule::GenerateDHKeyPair();
    auto t_dh_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.dhKeyGenTime = std::chrono::duration<double, std::micro>(t_dh_end - t_dh_start).count();

    // 生成时间戳（Unix 毫秒）
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    uint64_t timestamp = static_cast<uint64_t>(ms);

    // 生成随机 nonce（16 字节）
    CryptoModule::Bytes nonce(16);
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) {
        throw std::runtime_error("Failed to generate nonce");
    }
    session.timestamp = timestamp;
    session.nonce = nonce;
    // 签名内容：dhpubS || timestamp || nonce
    CryptoModule::Bytes sigInput = session.tempDH.publicKey;
    // 将 timestamp 按大端序序列化为 8 字节
    for (int i = 7; i >= 0; --i) {
        sigInput.push_back(static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF));
    }
    sigInput.insert(sigInput.end(), nonce.begin(), nonce.end());

    auto t_sign_start = std::chrono::high_resolution_clock::now();
    session.serversigm = CryptoModule::Sign(m_longTermKeys.privateKey, sigInput);
    auto t_sign_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.signTime = std::chrono::duration<double, std::micro>(t_sign_end - t_sign_start).count();

    m_activeSessions[uid] = session;

    auto t_challenge_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.challengeGenTime = std::chrono::duration<double, std::milli>(t_challenge_end - t_challenge_start).count();

    ProtocolMessages::AuthChallenge challenge;
    challenge.dhpubS = session.tempDH.publicKey;
    challenge.serversigm = session.serversigm;
    challenge.timestamp = timestamp;
    challenge.nonce = nonce;
    return challenge;
}

ProtocolMessages::AuthConfirmation Server::ProcessAuthResponse(const ProtocolMessages::AuthResponse& resp) {
    auto t_auth_start = std::chrono::high_resolution_clock::now();
    m_perfMetrics.totalAuthCount++;

    ProtocolMessages::AuthConfirmation confirmation;
    confirmation.success = false;

    // 1. 检查账户是否被锁定
    time_t now = time(nullptr);
    auto failIt = m_failureRecords.find(resp.uid);
    if (failIt != m_failureRecords.end()) {
        if (now < failIt->second.lockUntil) {
            int remainingSec = failIt->second.lockUntil - now;
            std::string lockMsg = "Account locked due to repeated failures. Retry in " + std::to_string(remainingSec) + " seconds.";
            BroadcastToMonitor("error", "🔒 账户已锁定", lockMsg);
            throw std::runtime_error(lockMsg);
        }
    }

    const char* sql_select = "SELECT pkSig, skEnc FROM users WHERE uid = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(m_db, sql_select, -1, &stmt, nullptr) != SQLITE_OK) throw std::runtime_error("Database read error");
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

    // 解密 skEnc 字段
    auto t_dbdec_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes db_skEnc = DecryptDBField(encryptedSkEnc);
    auto t_dbdec_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.dbDecryptTime = std::chrono::duration<double, std::micro>(t_dbdec_end - t_dbdec_start).count();

    auto sessionIt = m_activeSessions.find(resp.uid);
    if (sessionIt == m_activeSessions.end()) return confirmation;
    AuthSession& session = sessionIt->second;

    // ==========================================
    // 追踪 1：收到密文包裹
    // ==========================================
    std::string auditMsg1 = "【密文包裹 tau】:\n" + ToHex(resp.tau) + "\n\n";
    auditMsg1 += "【确认标签 tagU】:\n" + ToHex(resp.tagU) + "\n\n";
    auditMsg1 += "⚠️ 准备使用数据库存储的 sk_Enc 解密 tau。若终端指纹/口令错误引发了变异密钥，此步骤将立即崩溃拦截！";
    BroadcastToMonitor("warning", "📥 1. 收到终端认证挑战响应", auditMsg1);

    // ==========================================
    // 解密 tau 提取 sigma 和 dhpubU
    // ==========================================
    auto t_dec_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes decryptedPlaintext = CryptoModule::Decrypt(db_skEnc, resp.tau);
    auto t_dec_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.decryptTime = std::chrono::duration<double, std::micro>(t_dec_end - t_dec_start).count();
    
    if (decryptedPlaintext.size() < 4) throw std::runtime_error("Decrypted payload too short.");
    uint32_t sigLen = 0;
    sigLen |= (static_cast<uint32_t>(decryptedPlaintext[0]) << 24);
    sigLen |= (static_cast<uint32_t>(decryptedPlaintext[1]) << 16);
    sigLen |= (static_cast<uint32_t>(decryptedPlaintext[2]) << 8);
    sigLen |= static_cast<uint32_t>(decryptedPlaintext[3]);

    if (decryptedPlaintext.size() < 4 + sigLen) throw std::runtime_error("Decrypted payload size mismatch.");
    
    CryptoModule::Bytes sigma(decryptedPlaintext.begin() + 4, decryptedPlaintext.begin() + 4 + sigLen);
    CryptoModule::Bytes dhpubU(decryptedPlaintext.begin() + 4 + sigLen, decryptedPlaintext.end());

    // ==========================================
    // 追踪 2：解密成功
    // ==========================================
    std::string auditMsg2 = "✅ AEAD 解密成功 (验证终端加密密钥合法)！\n\n";
    auditMsg2 += "【提取出终端临时公钥 dhpubU】:\n" + ToHex(dhpubU) + "\n\n";
    auditMsg2 += "【提取出终端 ECDSA 签名 sigma】:\n" + ToHex(sigma);
    BroadcastToMonitor("success", "🔓 2. tau 解密与数据分离", auditMsg2);

    // ==========================================
    // 追踪 3：验证签名
    // ==========================================
    CryptoModule::Bytes sigInput(resp.uid.begin(), resp.uid.end());
    sigInput.insert(sigInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    sigInput.insert(sigInput.end(), dhpubU.begin(), dhpubU.end());
    sigInput.insert(sigInput.end(), resp.tagU.begin(), resp.tagU.end());

    auto t_verify_start = std::chrono::high_resolution_clock::now();
    if (!CryptoModule::VerifySignature(db_pkSig, sigInput, sigma)) {
        m_perfMetrics.failedAuthCount++;
        throw std::runtime_error("User signature verification failed! Illegal user.");
    }
    auto t_verify_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.verifyTime = std::chrono::duration<double, std::micro>(t_verify_end - t_verify_start).count();

    std::string auditMsg3 = "签名原文公式: uid || dhpubS || dhpubU || tagU\n\n";
    auditMsg3 += "💡 网关并不拥有用户私钥，而是提取注册时绑定的公钥进行非对称验签。\n\n";
    auditMsg3 += "【使用的验证公钥 pk_Sig】:\n" + ToHex(db_pkSig);
    BroadcastToMonitor("success", "✍️ 3. 终端 ECDSA 签名验证通过", auditMsg3);

    // ==========================================
    // 追踪 4：ECDH 共享秘密
    // ==========================================
    auto t_ecdh_start = std::chrono::high_resolution_clock::now();
    session.sharedSecret = CryptoModule::ComputeSharedSecret(session.tempDH.privateKey, dhpubU);
    auto t_ecdh_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.ecdhComputeTime = std::chrono::duration<double, std::micro>(t_ecdh_end - t_ecdh_start).count();

    BroadcastToMonitor("crypto", "🔑 4. 协商底层 ECDH 共享秘密", "公式: ECDH(网关临时私钥, 终端临时公钥 dhpubU)\n\n【计算出的 SharedSecret】:\n" + ToHex(session.sharedSecret));

    // ==========================================
    // 追踪 5：验证 tagU
    // ==========================================
    CryptoModule::Bytes expectedTagUInput = session.sharedSecret;
    expectedTagUInput.insert(expectedTagUInput.end(), resp.uid.begin(), resp.uid.end());
    expectedTagUInput.insert(expectedTagUInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    
    // 提取 Session 中保存的 timestamp 并按大端序加入
    for (int i = 7; i >= 0; --i) {
        expectedTagUInput.push_back(static_cast<uint8_t>((session.timestamp >> (i * 8)) & 0xFF));
    }
    // 提取 Session 中保存的 nonce 加入
    expectedTagUInput.insert(expectedTagUInput.end(), session.nonce.begin(), session.nonce.end());
    
    expectedTagUInput.insert(expectedTagUInput.end(), session.serversigm.begin(), session.serversigm.end());
    expectedTagUInput.insert(expectedTagUInput.end(), dhpubU.begin(), dhpubU.end());
    std::string confirmStr = "clientconfirm";
    expectedTagUInput.insert(expectedTagUInput.end(), confirmStr.begin(), confirmStr.end());
    
    CryptoModule::Bytes expectedTagU = CryptoModule::Hash(expectedTagUInput);
    if (expectedTagU != resp.tagU) {
        throw std::runtime_error("TagU verification failed! Shared secret mismatch.");
    }

    std::string auditMsg4 = "tagU 组成部分:\n";
    auditMsg4 += "1. SharedSecret: " + ToHex(session.sharedSecret).substr(0, 16) + "...\n";
    auditMsg4 += "2. uid: " + resp.uid + "\n";
    auditMsg4 += "3. dhpubS: " + ToHex(session.tempDH.publicKey).substr(0, 16) + "...\n";
    auditMsg4 += "4. timestamp: " + std::to_string(session.timestamp) + "\n";       // <--- 新增
    auditMsg4 += "5. nonce_S: " + ToHex(session.nonce) + "\n";                     // <--- 新增
    auditMsg4 += "6. serversigm: " + ToHex(session.serversigm).substr(0, 16) + "...\n";
    auditMsg4 += "7. dhpubU: " + ToHex(dhpubU).substr(0, 16) + "...\n";
    auditMsg4 += "8. 常量: 'clientconfirm'\n\n";
    auditMsg4 += "网关本地计算出的 tagU:\n" + ToHex(expectedTagU) + "\n\n";
    auditMsg4 += "✅ 比对结果：与终端上传的 tagU 完美匹配！";
    BroadcastToMonitor("success", "✅ 5. 终端确认标签 tagU 匹配通过", auditMsg4);

    // 派生会话密钥（使用 HKDF 两阶段密钥派生 + 双向密钥分离）
    // Extract: PRK = HKDF-Extract(salt=dhpubS||dhpubU, IKM=sharedSecret)
    auto t_hkdf_start = std::chrono::high_resolution_clock::now();
    CryptoModule::Bytes hkdfSalt = session.tempDH.publicKey;
    hkdfSalt.insert(hkdfSalt.end(), dhpubU.begin(), dhpubU.end());
    CryptoModule::Bytes prk = CryptoModule::HKDF_Extract(hkdfSalt, session.sharedSecret);

    // Expand: 从同一 PRK 派生双向独立密钥
    std::string c2sInfo = "c2s_" + resp.uid;
    std::string s2cInfo = "s2c_" + resp.uid;
    CryptoModule::Bytes c2sKey = CryptoModule::HKDF_Expand(prk,
        CryptoModule::Bytes(c2sInfo.begin(), c2sInfo.end()), 32);
    CryptoModule::Bytes s2cKey = CryptoModule::HKDF_Expand(prk,
        CryptoModule::Bytes(s2cInfo.begin(), s2cInfo.end()), 32);

    // 服务端：发送用 s2c_key，接收用 c2s_key
    session.sessionKey = CryptoModule::HKDF_Expand(prk,
        CryptoModule::Bytes({'s','e','s','s','i','o','n','k','e','y'}), 32);
    session.secureLayer.Initialize(s2cKey, c2sKey);
    auto t_hkdf_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.hkdfTime = std::chrono::duration<double, std::micro>(t_hkdf_end - t_hkdf_start).count();

    // ==========================================
    // 追踪 6：网关确认参数签发
    // ==========================================
    CryptoModule::Bytes tagSInput = session.sharedSecret;
    tagSInput.insert(tagSInput.end(), resp.uid.begin(), resp.uid.end());
    tagSInput.insert(tagSInput.end(), resp.tau.begin(), resp.tau.end());
    tagSInput.insert(tagSInput.end(), session.tempDH.publicKey.begin(), session.tempDH.publicKey.end());
    
    // --- 新增：大端序加入 timestamp ---
    for (int i = 7; i >= 0; --i) {
        tagSInput.push_back(static_cast<uint8_t>((session.timestamp >> (i * 8)) & 0xFF));
    }
    // --- 新增：加入 nonce_S ---
    tagSInput.insert(tagSInput.end(), session.nonce.begin(), session.nonce.end());

    tagSInput.insert(tagSInput.end(), resp.tagU.begin(), resp.tagU.end());
    std::string serverConfirmStr = "serverconfirm";
    tagSInput.insert(tagSInput.end(), serverConfirmStr.begin(), serverConfirmStr.end());
    
    confirmation.tagS = CryptoModule::Hash(tagSInput);
    confirmation.serversigtag = CryptoModule::Sign(m_longTermKeys.privateKey, confirmation.tagS);
    confirmation.success = true;

    std::string auditMsg5 = "tagS 组成部分:\n";
    auditMsg5 += "1. SharedSecret: " + ToHex(session.sharedSecret).substr(0, 16) + "...\n";
    auditMsg5 += "2. uid: " + resp.uid + "\n";
    auditMsg5 += "3. tau (密文): " + ToHex(resp.tau).substr(0, 16) + "...\n";
    auditMsg5 += "4. dhpubS: " + ToHex(session.tempDH.publicKey).substr(0, 16) + "...\n";
    auditMsg5 += "5. timestamp: " + std::to_string(session.timestamp) + "\n";       // <--- 新增
    auditMsg5 += "6. nonce_S: " + ToHex(session.nonce) + "\n";                     // <--- 新增
    auditMsg5 += "7. tagU: " + ToHex(resp.tagU).substr(0, 16) + "...\n";
    auditMsg5 += "8. 常量: 'serverconfirm'\n\n";
    auditMsg5 += "【生成网关确认标签 tagS】:\n" + ToHex(confirmation.tagS) + "\n\n";
    auditMsg5 += "【网关最终签名 serversigtag】:\n" + ToHex(confirmation.serversigtag);
    BroadcastToMonitor("crypto", "🏷️ 6. 签发网关反向确认参数", auditMsg5);
    // 认证成功：重置失败计数器
    m_failureRecords.erase(resp.uid);
    m_perfMetrics.successAuthCount++;

    auto t_auth_end = std::chrono::high_resolution_clock::now();
    m_perfMetrics.authVerifyTime = std::chrono::duration<double, std::milli>(t_auth_end - t_auth_start).count();
    m_perfMetrics.totalAuthTime = m_perfMetrics.authVerifyTime;

    return confirmation;
}

CryptoModule::Bytes Server::GetSessionKey(const std::string& uid) const {
    auto it = m_activeSessions.find(uid);
    if (it != m_activeSessions.end()) return it->second.sessionKey;
    return CryptoModule::Bytes();
}

// ==========================================
// 认证失败处理：指数退避 + 账户锁定
// ==========================================
void Server::HandleAuthFailure(const std::string& uid) {
    time_t now = time(nullptr);
    m_perfMetrics.failedAuthCount++;

    auto& record = m_failureRecords[uid];
    record.failCount++;
    record.lastFailTime = now;

    // 指数退避：backoff = min(2^failCount, 300) 秒
    int backoffSec = std::min(static_cast<int>(std::pow(2, record.failCount)), 300);

    // 连续失败 5 次：锁定 15 分钟
    if (record.failCount >= 5) {
        record.lockUntil = now + 900; // 15 分钟
        std::string lockMsg = "Account [" + uid + "] locked for 15 minutes after " + std::to_string(record.failCount) + " failed attempts.";
        BroadcastToMonitor("error", "🔒 账户锁定", lockMsg);
        std::cout << "[Server] " << lockMsg << "\n";
    } else {
        record.lockUntil = now + backoffSec;
        std::string backoffMsg = "Authentication failed for [" + uid + "]. Backoff: " + std::to_string(backoffSec) + " seconds (attempt " + std::to_string(record.failCount) + "/5).";
        BroadcastToMonitor("warning", "⚠️ 认证失败", backoffMsg);
        std::cout << "[Server] " << backoffMsg << "\n";
    }
    m_perfMetrics.failedAuthCount++;
}

// ==========================================
// 性能统计与报告导出
// ==========================================
PerformanceMetrics Server::GetPerformanceMetrics() const {
    return m_perfMetrics;
}

void Server::ExportPerformanceReport(const std::string& filepath) const {
    std::ofstream outfile(filepath);
    if (!outfile.is_open()) {
        throw std::runtime_error("Failed to open performance report file: " + filepath);
    }

    // CSV 表头
    outfile << "Metric,Value,Unit\n";

    // 密码学操作耗时（微秒）
    outfile << "DH Key Generation," << m_perfMetrics.dhKeyGenTime << ",us\n";
    outfile << "ECDH Compute," << m_perfMetrics.ecdhComputeTime << ",us\n";
    outfile << "ECDSA Sign," << m_perfMetrics.signTime << ",us\n";
    outfile << "ECDSA Verify," << m_perfMetrics.verifyTime << ",us\n";
    outfile << "ECIES Encrypt," << m_perfMetrics.encryptTime << ",us\n";
    outfile << "ECIES Decrypt," << m_perfMetrics.decryptTime << ",us\n";
    outfile << "HKDF Derivation," << m_perfMetrics.hkdfTime << ",us\n";
    outfile << "DB Field Encrypt," << m_perfMetrics.dbEncryptTime << ",us\n";
    outfile << "DB Field Decrypt," << m_perfMetrics.dbDecryptTime << ",us\n";

    // 协议阶段耗时（毫秒）
    outfile << "Registration Phase," << m_perfMetrics.registrationTime << ",ms\n";
    outfile << "Challenge Generation," << m_perfMetrics.challengeGenTime << ",ms\n";
    outfile << "Auth Verification," << m_perfMetrics.authVerifyTime << ",ms\n";
    outfile << "Total Auth Time," << m_perfMetrics.totalAuthTime << ",ms\n";

    // 统计计数
    outfile << "Total Auth Attempts," << m_perfMetrics.totalAuthCount << ",count\n";
    outfile << "Successful Auths," << m_perfMetrics.successAuthCount << ",count\n";
    outfile << "Failed Auths," << m_perfMetrics.failedAuthCount << ",count\n";

    // 成功率
    if (m_perfMetrics.totalAuthCount > 0) {
        double successRate = (double)m_perfMetrics.successAuthCount / m_perfMetrics.totalAuthCount * 100.0;
        outfile << "Success Rate," << successRate << ",%\n";
    }

    outfile.close();
    std::cout << "[Server] Performance report exported to: " << filepath << "\n";
}