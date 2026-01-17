#include "crow_all.h"
#include "Server.h"
#include "User.h"
#include "BioModule.h"
#include "SecureRecordLayer.h"
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_set>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
// --- Base64 与 Hex 工具 ---
std::string Base64Encode(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) return "";
    std::vector<uint8_t> encoded(4 * ((buffer.size() + 2) / 3) + 1);
    int len = EVP_EncodeBlock(encoded.data(), buffer.data(), buffer.size());
    return std::string(encoded.begin(), encoded.begin() + len);
}

std::vector<uint8_t> Base64Decode(const std::string& input) {
    if (input.empty()) return {};
    std::vector<uint8_t> decoded(input.size());
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    int outl = 0, totall = 0;
    if (EVP_DecodeUpdate(ctx, decoded.data(), &outl, reinterpret_cast<const uint8_t*>(input.data()), input.size()) < 0) {
        EVP_ENCODE_CTX_free(ctx); return {};
    }
    totall = outl;
    if (EVP_DecodeFinal(ctx, decoded.data() + outl, &outl) < 0) {
        EVP_ENCODE_CTX_free(ctx); return {};
    }
    totall += outl;
    decoded.resize(totall);
    EVP_ENCODE_CTX_free(ctx);
    return decoded;
}

std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ========================================================
// 核心状态机与大屏监控广播通道
// ========================================================
Server gateway;
std::unique_ptr<User> virtualDevice = nullptr;

// 监控大屏的 WebSocket 连接池
std::unordered_set<crow::websocket::connection*> monitor_connections;
std::mutex monitor_mtx;
std::unordered_set<crow::websocket::connection*> device_connections;
std::mutex device_mtx;

void BroadcastToMonitor(const std::string& event, const std::string& title, const std::string& details) {
    crow::json::wvalue msg;
    msg["event"] = event;
    msg["title"] = title;
    msg["details"] = details;
    std::string dump = msg.dump();

    std::lock_guard<std::mutex> lock(monitor_mtx);
    for (auto* conn : monitor_connections) {
        conn->send_text(dump);
    }
}

// 性能数据广播（每 2 秒推送一次到 Web 大屏）
void BroadcastPerformanceMetrics() {
    PerformanceMetrics metrics = gateway.GetPerformanceMetrics();

    crow::json::wvalue perfMsg;
    perfMsg["event"] = "performance";
    perfMsg["dhKeyGenTime"] = metrics.dhKeyGenTime;
    perfMsg["ecdhComputeTime"] = metrics.ecdhComputeTime;
    perfMsg["signTime"] = metrics.signTime;
    perfMsg["verifyTime"] = metrics.verifyTime;
    perfMsg["encryptTime"] = metrics.encryptTime;
    perfMsg["decryptTime"] = metrics.decryptTime;
    perfMsg["hkdfTime"] = metrics.hkdfTime;
    perfMsg["dbEncryptTime"] = metrics.dbEncryptTime;
    perfMsg["dbDecryptTime"] = metrics.dbDecryptTime;
    perfMsg["registrationTime"] = metrics.registrationTime;
    perfMsg["challengeGenTime"] = metrics.challengeGenTime;
    perfMsg["authVerifyTime"] = metrics.authVerifyTime;
    perfMsg["totalAuthTime"] = metrics.totalAuthTime;
    perfMsg["totalAuthCount"] = metrics.totalAuthCount;
    perfMsg["successAuthCount"] = metrics.successAuthCount;
    perfMsg["failedAuthCount"] = metrics.failedAuthCount;

    std::string dump = perfMsg.dump();
    std::lock_guard<std::mutex> lock(monitor_mtx);
    for (auto* conn : monitor_connections) {
        conn->send_text(dump);
    }
}

int main() {
    crow::SimpleApp app;
    // ==========================================
    // 【新增】：UDP 局域网零配置发现机制 (Zero-Conf)
    // ==========================================
    std::thread udpBroadcaster([]() {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
	int opt = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (sock < 0) {
            std::cerr << "[UDP] Failed to create broadcast socket.\n";
            return;
        }

        // 开启广播权限
        int broadcastEnable = 1;
        setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));

        sockaddr_in broadcastAddr;
        memset(&broadcastAddr, 0, sizeof(broadcastAddr));
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_port = htons(9999); // 约定端口 9999
        broadcastAddr.sin_addr.s_addr = inet_addr("255.255.255.255"); // 全局域网广播

        std::string magic_msg = "IOT_AUTH_GATEWAY_v1";

        std::cout << "[UDP] 局域网广播线程已启动，等待手机端自动发现...\n";
        while (true) {
            sendto(sock, magic_msg.c_str(), magic_msg.length(), 0, 
                  (sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
            std::this_thread::sleep_for(std::chrono::seconds(2)); // 每 2 秒大喊一次
        }
    });
    udpBroadcaster.detach(); // 脱离主线程独立运行
    gateway.ClearDatabase();

    // 启动性能数据广播线程（每 2 秒推送一次）
    std::thread perfThread([]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            BroadcastPerformanceMetrics();
        }
    });
    perfThread.detach();

    // API 1: 重置网关数据库
    CROW_ROUTE(app, "/api/reset").methods("POST"_method, "OPTIONS"_method)([&](const crow::request& req){
        // 1. 处理浏览器的 CORS 跨域预检请求
        if (req.method == crow::HTTPMethod::OPTIONS) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        try {
            // 2. 执行核心清理逻辑
            gateway.ClearDatabase();

            BroadcastToMonitor("system", "系统重置", "数据库与所有安全凭证已被清空");
            
            // 3. 向所有在线的 Android 设备广播“强制踢下线”指令
            std::lock_guard<std::mutex> lock(device_mtx);
            for (auto* conn : device_connections) {
                conn->send_text("{\"type\": \"system_reset\"}");
            }
            
            // 4. 返回成功，并附带跨域头
            crow::response res(200, "{\"status\":\"success\"}");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            crow::response res(500, e.what());
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // API 3: 导出性能报告
    CROW_ROUTE(app, "/api/performance/export").methods("GET"_method)([&](const crow::request& req){
        try {
            std::string filepath = "performance_report.csv";
            gateway.ExportPerformanceReport(filepath);

            crow::response res(200, "{\"status\":\"success\", \"file\":\"" + filepath + "\"}");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            crow::response res(500, e.what());
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // API 2: 注册
    CROW_ROUTE(app, "/api/register").methods("POST"_method)([&](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        try {
            std::string uid = body["uid"].s();
            std::string pkSigStr = body["avk_pkSig"].s();
            std::string skEncStr = body["avk_skEnc"].s();

            // ==========================================
            // 【新增】：向大屏广播完整的注册凭证
            // ==========================================
            std::string auditMsg = "【设备 UID】: " + uid + "\n\n";
            auditMsg += "【签名公钥 pk_Sig】:\n" + pkSigStr + "\n\n";
            auditMsg += "【解密密钥 sk_Enc】:\n" + skEncStr;
            BroadcastToMonitor("crypto", "📥 收到设备注册载荷", auditMsg);

            // 2. 将 Hex 字符串解码为底层的 Bytes 
            ProtocolMessages::RegistrationRequest regReq;
            regReq.uid = uid;
            
            //把 Hex 字符串转换回二进制数组塞进请求体
            regReq.avk_pkSig = HexToBytes(pkSigStr);
            regReq.avk_skEnc = HexToBytes(skEncStr);

            // 3. 将真实请求塞给网关状态机处理（签名并存入 SQLite）
            ProtocolMessages::RegistrationResponse regResp = gateway.ProcessRegistration(regReq);
            
            BroadcastToMonitor("crypto", "注册完成，下发网关凭证", "网关签名公钥(Hex): " + BytesToHex(regResp.serversigpk));

            crow::json::wvalue res;
            res["status"] = "success";
            res["serversigpk"] = Base64Encode(regResp.serversigpk);
            return crow::response(200, res);
        } catch (const std::exception& e) {
            return crow::response(500, e.what());
        }
    });

    // ==========================================
    // 新增：专供 Web Vue 大屏监听的通道
    // ==========================================
    CROW_WEBSOCKET_ROUTE(app, "/ws/monitor")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> lock(monitor_mtx);
            monitor_connections.insert(&conn);
            std::cout << "[Monitor] Web 大屏监控已接入。\n";
        })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason) {
            std::lock_guard<std::mutex> lock(monitor_mtx);
            monitor_connections.erase(&conn);
        });

    // ==========================================
    // Android 设备的真实业务通道
    // ==========================================
    CROW_WEBSOCKET_ROUTE(app, "/ws/auth")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> lock(device_mtx);
            device_connections.insert(&conn); // 【新增】加入连接池
        })
        .onclose([&](crow::websocket::connection& conn, const std::string& reason) {
            std::lock_guard<std::mutex> lock(device_mtx);
            device_connections.erase(&conn); // 【新增】移出连接池
        })
        .onmessage([&](crow::websocket::connection& conn, const std::string& data, bool is_binary) {
            auto body = crow::json::load(data);
            if (!body) return;
            std::string msg_type = body["type"].s();

            try {
                if (msg_type == "auth_request") {
                    std::string uid = body["uid"].s();
                    BroadcastToMonitor("crypto", "收到认证请求", "开始为 UID [" + uid + "] 生成挑战参数...");

                    ProtocolMessages::AuthChallenge challenge = gateway.GenerateAuthChallenge(uid);

                    std::string details = "1. 生成 ECDH 临时公钥: " + BytesToHex(challenge.dhpubS).substr(0, 40) + "...\n";
                    details += "2. 生成时间戳: " + std::to_string(challenge.timestamp) + " (Unix ms)\n";
                    details += "3. 生成随机 nonce: " + BytesToHex(challenge.nonce) + "\n";
                    details += "4. 使用网关长期私钥进行 ECDSA 签名\n";
                    details += "5. 签名结果 (Hex): " + BytesToHex(challenge.serversigm).substr(0, 40) + "...";
                    BroadcastToMonitor("crypto", "下发挑战包 (Challenge)", details);

                    crow::json::wvalue step1;
                    step1["type"] = "auth_challenge";
                    step1["dhpubS"] = Base64Encode(challenge.dhpubS);
                    step1["serversigm"] = Base64Encode(challenge.serversigm);
                    step1["timestamp"] = challenge.timestamp;
                    step1["nonce"] = Base64Encode(challenge.nonce);
                    conn.send_text(step1.dump());
                }
                else if (msg_type == "auth_response") {
                    std::string uid = body["uid"].s();
                    ProtocolMessages::AuthResponse authResp;
                    authResp.uid = uid;
                    authResp.tau = Base64Decode(body["tau"].s());
                    authResp.tagU = Base64Decode(body["tagU"].s());

                    BroadcastToMonitor("crypto", "收到客户端挑战响应", "收到密文包裹 tau 及认证标签 tagU。\n开始解析...");

                    try {
                        ProtocolMessages::AuthConfirmation confirmation = gateway.ProcessAuthResponse(authResp);

                        if (confirmation.success) {
                            std::string skHex = BytesToHex(gateway.GetSessionKey(uid));
                            BroadcastToMonitor("success", "双向认证彻底成功", "安全层初始化完毕。\n派生出会话密钥 (SessionKey): " + skHex + "\n等待业务指令...");
                        }

                        crow::json::wvalue step3;
                        step3["type"] = "auth_confirmation";
                        step3["success"] = confirmation.success;
                        if (confirmation.success) {
                            step3["tagS"] = Base64Encode(confirmation.tagS);
                            step3["serversigtag"] = Base64Encode(confirmation.serversigtag);
                        }
                        conn.send_text(step3.dump());
                    } catch (const std::exception& e) {
                        // 认证失败：记录失败并应用退避策略
                        gateway.HandleAuthFailure(uid);

                        crow::json::wvalue errResp;
                        errResp["type"] = "auth_confirmation";
                        errResp["success"] = false;
                        errResp["error"] = e.what();
                        conn.send_text(errResp.dump());
                    }
                }
                else if (msg_type == "secure_command") {
                    std::string uid = body["uid"].s();
                    std::string encryptedPayloadB64 = body["command"].s();

                    BroadcastToMonitor("crypto", "📥 收到 AEAD 加密数据", "Base64密文: " + encryptedPayloadB64);

                    auto sessionIt = gateway.m_activeSessions.find(uid);
                    if (sessionIt == gateway.m_activeSessions.end()) throw std::runtime_error("Session not found");
                    AuthSession& session = sessionIt->second;

                    CryptoModule::Bytes ciphertext = Base64Decode(encryptedPayloadB64);
                    std::string plaintextCmd = session.secureLayer.UnprotectRecord(ciphertext);
                    
                    BroadcastToMonitor("success", "🔓 ChaCha20 解密与 Tag 验证通过", "解密出的原始指令: " + plaintextCmd);

                    // 通知前端动画更新
                    BroadcastToMonitor("device_sync", "执行设备指令", plaintextCmd);

                    std::string feedbackJson = "{\"status\":\"success\", \"executed_command\":" + plaintextCmd + "}";
                    CryptoModule::Bytes respCiphertext = session.secureLayer.ProtectRecord(feedbackJson);

                    BroadcastToMonitor("crypto", "📤 组装回执并加密", "准备将结果加密发回 Android...");

                    crow::json::wvalue res;
                    res["type"] = "command_result";
                    res["payload"] = Base64Encode(respCiphertext);
                    conn.send_text(res.dump());
                }
            } catch (const std::exception& e) {
                BroadcastToMonitor("error", "🛑 密码学防御机制触发", e.what());
                crow::json::wvalue err; err["type"] = "error"; err["message"] = e.what();
                conn.send_text(err.dump());
            }
        });

    app.bindaddr("0.0.0.0").port(8081).multithreaded().run();
    return 0;
}