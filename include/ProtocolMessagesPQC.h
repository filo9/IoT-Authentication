#pragma once

#include <string>
#include <vector>
#include "CryptoModule.h"

namespace ProtocolMessagesPQC {

    using Bytes = CryptoModule::Bytes;

    // =========================================================
    // 阶段一：注册阶段 (与原协议完全一致)
    // =========================================================

    struct RegistrationRequest {
        std::string uid;
        Bytes avk_pkSig;
        Bytes avk_skEnc;
    };

    struct RegistrationResponse {
        bool success;
        Bytes serversigpk;
    };

    // =========================================================
    // 阶段二：后量子认证与密钥协商阶段
    // =========================================================

    // 步骤 1: 客户端发起登录请求
    struct PQCAuthRequest {
        std::string uid;
    };

    // 步骤 2: 服务器响应挑战 — pk_KEM 替代 dhpubS
    struct PQCAuthChallenge {
        Bytes pkKEM;               // ML-KEM-768 临时公钥 (1184 bytes)
        Bytes serversigm;          // Sign(sk_server, pk_KEM)
        uint64_t timestamp;
        Bytes nonce;
    };

    // 步骤 3: 客户端响应 — ct 替代 dhpubU
    struct PQCAuthResponse {
        std::string uid;
        Bytes tau;                 // Enc(pkEnc, sigma || ct)
        Bytes tagU;                // H(shared_secret || uid || pk_KEM || server_sigm || ct || "clientconfirm")
    };

    // 步骤 4: 服务器验证与确认
    struct PQCAuthConfirmation {
        bool success;
        Bytes tagS;                // H(shared_secret || uid || tau || pk_KEM || tagU || "serverconfirm")
        Bytes serversigtag;        // Sign(sk_server, tagS)
    };

} // namespace ProtocolMessagesPQC
