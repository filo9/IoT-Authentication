#include "SecureRecordLayer.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdexcept>
#include <iostream>
#include <memory>

SecureRecordLayer::SecureRecordLayer() : m_sendSeq(0), m_recvSeq(0) {}

using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

void SecureRecordLayer::Initialize(const CryptoModule::Bytes& sendKey, const CryptoModule::Bytes& recvKey) {
    if (sendKey.size() != CHACHA20_KEY_LEN || recvKey.size() != CHACHA20_KEY_LEN) {
        throw std::runtime_error("Both keys must be exactly 32 bytes for ChaCha20-Poly1305.");
    }
    m_sendKey = sendKey;
    m_recvKey = recvKey;
    m_sendSeq = 1;
    m_recvSeq = 0;
}

void SecureRecordLayer::InitializeSingleKey(const CryptoModule::Bytes& sessionKey) {
    Initialize(sessionKey, sessionKey);
}

CryptoModule::Bytes SecureRecordLayer::ConstructNonce(uint32_t seq) {
    // RFC 7539: Nonce 为 96 bit (12 bytes). 
    // 我们将 32 bit 序列号以大端序放入 Nonce 的最后 4 个字节，前面补零。
    CryptoModule::Bytes nonce(CHACHA20_IV_LEN, 0x00);
    nonce[8] = (seq >> 24) & 0xFF;
    nonce[9] = (seq >> 16) & 0xFF;
    nonce[10] = (seq >> 8) & 0xFF;
    nonce[11] = seq & 0xFF;
    return nonce;
}

CryptoModule::Bytes SecureRecordLayer::ProtectRecord(const std::string& plaintextCommand) {
    if (m_sendKey.empty()) throw std::runtime_error("Secure record layer not initialized.");

    // 1. 构造当前发送序列号的 Nonce
    CryptoModule::Bytes nonce = ConstructNonce(m_sendSeq);

    // 2. 初始化 ChaCha20-Poly1305 加密上下文（使用发送密钥）
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, m_sendKey.data(), nonce.data()) != 1) {
        throw std::runtime_error("Failed to init ChaCha20-Poly1305");
    }

    // AAD (附加认证数据): 可以把序列号作为 AAD 绑进去，进一步防篡改
    uint8_t aad[4] = {nonce[8], nonce[9], nonce[10], nonce[11]};
    int len = 0;
    EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad, sizeof(aad));

    // 3. 加密 Payload
    CryptoModule::Bytes ciphertext(plaintextCommand.size() + EVP_CIPHER_block_size(EVP_chacha20_poly1305()));
    int ciphertext_len = 0;
    EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, 
                      reinterpret_cast<const uint8_t*>(plaintextCommand.data()), plaintextCommand.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // 4. 获取 Poly1305 Tag (16 字节)
    CryptoModule::Bytes tag(POLY1305_TAG_LEN);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, POLY1305_TAG_LEN, tag.data());

    // 5. TLV 封包: [Payload长度(4)] || [Nonce(12)] || [Tag(16)] || [密文]
    CryptoModule::Bytes packet;
    uint32_t payloadLen = ciphertext.size();
    
    // 序列化长度 (大端序，方便 Java 端使用 ByteBuffer.getInt() 直接解析)
    uint8_t lenBytes[4] = {
        static_cast<uint8_t>((payloadLen >> 24) & 0xFF), static_cast<uint8_t>((payloadLen >> 16) & 0xFF),
        static_cast<uint8_t>((payloadLen >> 8) & 0xFF), static_cast<uint8_t>(payloadLen & 0xFF)
    };
    
    packet.insert(packet.end(), lenBytes, lenBytes + 4);
    packet.insert(packet.end(), nonce.begin(), nonce.end());
    packet.insert(packet.end(), tag.begin(), tag.end());
    packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());

    m_sendSeq++; // 发送完毕，序列号自增
    return packet;
}

std::string SecureRecordLayer::UnprotectRecord(const CryptoModule::Bytes& securePacket) {
    if (m_recvKey.empty()) throw std::runtime_error("Secure record layer not initialized.");
    
    // 1. 校验包的最小长度 (4 + 12 + 16 = 32 字节)
    const size_t MIN_PACKET_LEN = 4 + CHACHA20_IV_LEN + POLY1305_TAG_LEN;
    if (securePacket.size() < MIN_PACKET_LEN) throw std::runtime_error("Secure packet too short.");

    // 2. 跨平台解析解包 (对应 Java 端的读取逻辑)
    uint32_t payloadLen = (static_cast<uint32_t>(securePacket[0]) << 24) |
                          (static_cast<uint32_t>(securePacket[1]) << 16) |
                          (static_cast<uint32_t>(securePacket[2]) << 8) |
                           static_cast<uint32_t>(securePacket[3]);

    if (securePacket.size() != MIN_PACKET_LEN + payloadLen) {
        throw std::runtime_error("Secure packet length mismatch or corrupted.");
    }

    CryptoModule::Bytes nonce(securePacket.begin() + 4, securePacket.begin() + 4 + CHACHA20_IV_LEN);
    CryptoModule::Bytes tag(securePacket.begin() + 16, securePacket.begin() + 32);
    CryptoModule::Bytes ciphertext(securePacket.begin() + 32, securePacket.end());

    // 3. 提取序列号，进行防重放校验 (极其关键！)
    uint32_t incomingSeq = (static_cast<uint32_t>(nonce[8]) << 24) | (static_cast<uint32_t>(nonce[9]) << 16) |
                           (static_cast<uint32_t>(nonce[10]) << 8) | static_cast<uint32_t>(nonce[11]);
    
    if (incomingSeq <= m_recvSeq) {
        throw std::runtime_error("Replay Attack Detected! Incoming sequence number is expired.");
    }

    // 4. ChaCha20-Poly1305 解密与认证（使用接收密钥）
    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, m_recvKey.data(), nonce.data()) != 1) {
        throw std::runtime_error("Failed to init ChaCha20-Poly1305 decryption");
    }

    // 验证 AAD
    uint8_t aad[4] = {nonce[8], nonce[9], nonce[10], nonce[11]};
    int len = 0;
    EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad, sizeof(aad));

    CryptoModule::Bytes plaintext(ciphertext.size());
    EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, POLY1305_TAG_LEN, tag.data());
    
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw std::runtime_error("Record Authentication Failed! Data tampered or wrong session key.");
    }
    plaintext_len += len;

    // 5. 解密成功，正式更新高水位序列号
    m_recvSeq = incomingSeq;

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}