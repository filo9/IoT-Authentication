#pragma once

#include <string>
#include <vector>
#include "CryptoModule.h"

namespace ProtocolMessages {

    using Bytes = CryptoModule::Bytes;

    // =========================================================
    // 阶段一：注册阶段 (Registration Phase)
    // =========================================================

    // 用户发送给服务器的注册包
    struct RegistrationRequest {
        std::string uid;           // 用户ID [cite: 162]
        // 凭证 avk 的组成部分 [cite: 161]
        Bytes avk_pkSig;           // 用户的签名公钥
        Bytes avk_skEnc;           // 用户的解密私钥 (交给服务器托管)
    };

    // 服务器返回给用户的注册响应
    struct RegistrationResponse {
        bool success;
        Bytes serversigpk;         // 服务器的长期签名公钥 (让用户保存到本地) [cite: 165]
    };

    // =========================================================
    // 阶段二：认证与密钥协商阶段 (Authentication Phase)
    // =========================================================

    // 步骤 1: 客户端发起登录请求 [cite: 173-174]
    struct AuthRequest {
        std::string uid;           // 用户ID
    };

    // 步骤 2: 服务器响应挑战 [cite: 175-178]
    struct AuthChallenge {
        Bytes dhpubS;              // 服务器生成的临时 DH 公钥
        Bytes serversigm;          // 服务器对 dhpubS || timestamp || nonce 的签名 (防篡改 + 防重放)
        uint64_t timestamp;        // 挑战生成时间戳（Unix 毫秒）
        Bytes nonce;               // 随机 nonce（16 字节）
    };

    // 步骤 3: 客户端响应挑战 [cite: 179-191]
    struct AuthResponse {
        std::string uid;           // 用户ID
        Bytes tau;                 // 加密后的载荷 (内含用户签名 sigma 和 临时 DH 公钥 dhpubU) [cite: 189]
        Bytes tagU;                // 用户确认标签 (绑定上下文) [cite: 187]
    };

    // 步骤 4: 服务器验证与确认 [cite: 192-201]
    struct AuthConfirmation {
        bool success;              // 验证是否成功
        Bytes tagS;                // 服务器确认标签 [cite: 199]
        Bytes serversigtag;        // 服务器对 tagS 的最终签名 [cite: 200]
    };

} // namespace ProtocolMessages