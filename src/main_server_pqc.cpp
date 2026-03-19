#include "crow_all.h"
#include "ServerPQC.h"
#include "UserPQC.h"
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

// --- Base64 与 Hex 工具 (PQC 版本，避免符号冲突) ---
static std::string B64EncodePQC(const std::vector<uint8_t>& buffer) {
    if (buffer.empty()) return "";
    std::vector<uint8_t> encoded(4 * ((buffer.size() + 2) / 3) + 1);
    int len = EVP_EncodeBlock(encoded.data(), buffer.data(), buffer.size());
    return std::string(encoded.begin(), encoded.begin() + len);
}

static std::vector<uint8_t> B64DecodePQC(const std::string& input) {
    if (input.empty()) return {};
    std::vector<uint8_t> decoded(input.size());
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    EVP_DecodeInit(ctx);
    int outl = 0, totall = 0;
    if (EVP_DecodeUpdate(ctx, decoded.data(), &outl,
            reinterpret_cast<const uint8_t*>(input.data()), input.size()) < 0) {
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

static std::vector<uint8_t> HexToBytesPQC(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

static std::string BytesToHexPQC(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (unsigned char b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

// ========================================================
// PQC 网关状态机与监控广播
// ========================================================
ServerPQC gatewayPQC;

std::unordered_set<crow::websocket::connection*> pqc_monitor_connections;
std::mutex pqc_monitor_mtx;
std::unordered_set<crow::websocket::connection*> pqc_device_connections;
std::mutex pqc_device_mtx;

void BroadcastToMonitorPQC(const std::string& event, const std::string& title, const std::string& details) {
    crow::json::wvalue msg;
    msg["event"] = event;
    msg["title"] = title;
    msg["details"] = details;
    std::string dump = msg.dump();

    std::lock_guard<std::mutex> lock(pqc_monitor_mtx);
    for (auto* conn : pqc_monitor_connections) {
        conn->send_text(dump);
    }
}

void BroadcastPQCPerformanceMetrics() {
    PQCPerformanceMetrics metrics = gatewayPQC.GetPerformanceMetrics();

    crow::json::wvalue m;
    m["event"] = "performance";
    m["kemKeyGenTime"] = metrics.kemKeyGenTime;
    m["kemEncapsTime"] = metrics.kemEncapsTime;
    m["kemDecapsTime"] = metrics.kemDecapsTime;
    m["signTime"] = metrics.signTime;
    m["verifyTime"] = metrics.verifyTime;
    m["encryptTime"] = metrics.encryptTime;
    m["decryptTime"] = metrics.decryptTime;
    m["hkdfTime"] = metrics.hkdfTime;
    m["dbEncryptTime"] = metrics.dbEncryptTime;
    m["dbDecryptTime"] = metrics.dbDecryptTime;
    m["registrationTime"] = metrics.registrationTime;
    m["challengeGenTime"] = metrics.challengeGenTime;
    m["authVerifyTime"] = metrics.authVerifyTime;
    m["totalAuthTime"] = metrics.totalAuthTime;
    m["totalAuthCount"] = metrics.totalAuthCount;
    m["successAuthCount"] = metrics.successAuthCount;
    m["failedAuthCount"] = metrics.failedAuthCount;
    m["kemPublicKeySize"] = metrics.kemPublicKeySize;
    m["kemCiphertextSize"] = metrics.kemCiphertextSize;
    m["kemSharedSecretSize"] = metrics.kemSharedSecretSize;

    std::string dump = m.dump();
    std::lock_guard<std::mutex> lock(pqc_monitor_mtx);
    for (auto* conn : pqc_monitor_connections) {
        conn->send_text(dump);
    }
}

int main() {
    crow::SimpleApp app;
    gatewayPQC.ClearDatabase();

    std::cout << "========================================\n";
    std::cout << "  Post-Quantum IoT Gateway (ML-KEM-768)\n";
    std::cout << "  Port: 8082\n";
    std::cout << "========================================\n";

    // 性能广播线程
    std::thread perfThread([]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            BroadcastPQCPerformanceMetrics();
        }
    });
    perfThread.detach();

    // API: 重置
    CROW_ROUTE(app, "/api/reset").methods("POST"_method, "OPTIONS"_method)
    ([&](const crow::request& req) {
        if (req.method == crow::HTTPMethod::OPTIONS) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }
        try {
            gatewayPQC.ClearDatabase();
            BroadcastToMonitorPQC("system", "PQC System Reset", "Database and sessions cleared");
            crow::response res(200, "{\"status\":\"success\"}");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            crow::response res(500, e.what());
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // API: 导出性能报告
    CROW_ROUTE(app, "/api/performance/export").methods("GET"_method)
    ([&](const crow::request&) {
        try {
            std::string filepath = "performance_report_pqc.csv";
            gatewayPQC.ExportPerformanceReport(filepath);
            crow::response res(200, "{\"status\":\"success\", \"file\":\"" + filepath + "\"}");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        } catch (const std::exception& e) {
            crow::response res(500, e.what());
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
    });

    // API: 注册
    CROW_ROUTE(app, "/api/register").methods("POST"_method)
    ([&](const crow::request& req) {
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON");

        try {
            std::string uid = body["uid"].s();
            std::string pkSigStr = body["avk_pkSig"].s();
            std::string skEncStr = body["avk_skEnc"].s();

            BroadcastToMonitorPQC("crypto", "PQC Registration",
                "UID: " + uid + "\npk_Sig: " + pkSigStr.substr(0, 40) + "...");

            ProtocolMessagesPQC::RegistrationRequest regReq;
            regReq.uid = uid;
            regReq.avk_pkSig = HexToBytesPQC(pkSigStr);
            regReq.avk_skEnc = HexToBytesPQC(skEncStr);

            auto regResp = gatewayPQC.ProcessRegistration(regReq);

            BroadcastToMonitorPQC("success", "PQC Registration Complete",
                "Server PK: " + BytesToHexPQC(regResp.serversigpk).substr(0, 40) + "...");

            crow::json::wvalue res;
            res["status"] = "success";
            res["serversigpk"] = B64EncodePQC(regResp.serversigpk);
            return crow::response(200, res);
        } catch (const std::exception& e) {
            return crow::response(500, e.what());
        }
    });

    // WebSocket: 监控大屏
    CROW_WEBSOCKET_ROUTE(app, "/ws/monitor_pqc")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> lock(pqc_monitor_mtx);
            pqc_monitor_connections.insert(&conn);
            std::cout << "[PQC Monitor] Web dashboard connected.\n";
        })
        .onclose([&](crow::websocket::connection& conn, const std::string&) {
            std::lock_guard<std::mutex> lock(pqc_monitor_mtx);
            pqc_monitor_connections.erase(&conn);
        });

    // WebSocket: 认证通道
    CROW_WEBSOCKET_ROUTE(app, "/ws/auth_pqc")
        .onopen([&](crow::websocket::connection& conn) {
            std::lock_guard<std::mutex> lock(pqc_device_mtx);
            pqc_device_connections.insert(&conn);
        })
        .onclose([&](crow::websocket::connection& conn, const std::string&) {
            std::lock_guard<std::mutex> lock(pqc_device_mtx);
            pqc_device_connections.erase(&conn);
        })
        .onmessage([&](crow::websocket::connection& conn, const std::string& data, bool) {
            auto body = crow::json::load(data);
            if (!body) return;
            std::string msg_type = body["type"].s();

            try {
                if (msg_type == "auth_request") {
                    std::string uid = body["uid"].s();
                    BroadcastToMonitorPQC("crypto", "PQC Auth Request",
                        "Generating ML-KEM-768 challenge for " + uid);

                    auto challenge = gatewayPQC.GenerateAuthChallenge(uid);

                    std::string details = "ML-KEM-768 pk_KEM size: " +
                        std::to_string(challenge.pkKEM.size()) + " bytes\n";
                    details += "Timestamp: " + std::to_string(challenge.timestamp) + "\n";
                    details += "Nonce: " + BytesToHexPQC(challenge.nonce) + "\n";
                    details += "Server signature on pk_KEM: " +
                        BytesToHexPQC(challenge.serversigm).substr(0, 40) + "...";
                    BroadcastToMonitorPQC("crypto", "PQC Challenge Sent", details);

                    crow::json::wvalue resp;
                    resp["type"] = "auth_challenge";
                    resp["pkKEM"] = B64EncodePQC(challenge.pkKEM);
                    resp["serversigm"] = B64EncodePQC(challenge.serversigm);
                    resp["timestamp"] = challenge.timestamp;
                    resp["nonce"] = B64EncodePQC(challenge.nonce);
                    conn.send_text(resp.dump());
                }
                else if (msg_type == "auth_response") {
                    std::string uid = body["uid"].s();
                    ProtocolMessagesPQC::PQCAuthResponse authResp;
                    authResp.uid = uid;
                    authResp.tau = B64DecodePQC(body["tau"].s());
                    authResp.tagU = B64DecodePQC(body["tagU"].s());

                    BroadcastToMonitorPQC("crypto", "PQC Auth Response Received",
                        "Processing ML-KEM decapsulation for " + uid);

                    try {
                        auto confirmation = gatewayPQC.ProcessAuthResponse(authResp);

                        if (confirmation.success) {
                            std::string skHex = BytesToHexPQC(gatewayPQC.GetSessionKey(uid));
                            BroadcastToMonitorPQC("success", "PQC Mutual Auth Complete",
                                "Session key: " + skHex);
                        }

                        crow::json::wvalue resp;
                        resp["type"] = "auth_confirmation";
                        resp["success"] = confirmation.success;
                        if (confirmation.success) {
                            resp["tagS"] = B64EncodePQC(confirmation.tagS);
                            resp["serversigtag"] = B64EncodePQC(confirmation.serversigtag);
                        }
                        conn.send_text(resp.dump());
                    } catch (const std::exception& e) {
                        gatewayPQC.HandleAuthFailure(uid);
                        crow::json::wvalue errResp;
                        errResp["type"] = "auth_confirmation";
                        errResp["success"] = false;
                        errResp["error"] = e.what();
                        conn.send_text(errResp.dump());
                    }
                }
                else if (msg_type == "secure_command") {
                    std::string uid = body["uid"].s();
                    std::string encPayload = body["command"].s();

                    BroadcastToMonitorPQC("crypto", "PQC Encrypted Command",
                        "Ciphertext: " + encPayload.substr(0, 40) + "...");

                    auto sessionIt = gatewayPQC.m_activeSessions.find(uid);
                    if (sessionIt == gatewayPQC.m_activeSessions.end())
                        throw std::runtime_error("PQC session not found");

                    auto& session = sessionIt->second;
                    CryptoModule::Bytes ct = B64DecodePQC(encPayload);
                    std::string plainCmd = session.secureLayer.UnprotectRecord(ct);

                    BroadcastToMonitorPQC("success", "PQC Decrypted Command", plainCmd);
                    BroadcastToMonitorPQC("device_sync", "Execute", plainCmd);

                    std::string feedback = "{\"status\":\"success\", \"executed_command\":" + plainCmd + "}";
                    CryptoModule::Bytes respCt = session.secureLayer.ProtectRecord(feedback);

                    crow::json::wvalue res;
                    res["type"] = "command_result";
                    res["payload"] = B64EncodePQC(respCt);
                    conn.send_text(res.dump());
                }
            } catch (const std::exception& e) {
                BroadcastToMonitorPQC("error", "PQC Error", e.what());
                crow::json::wvalue err;
                err["type"] = "error";
                err["message"] = e.what();
                conn.send_text(err.dump());
            }
        });

    app.port(8082).multithreaded().run();
    return 0;
}
