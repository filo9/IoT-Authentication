#include <iostream>
#include <iomanip>
#include <string>
#include "User.h"
#include "Server.h"
#include "BioModule.h"
#include "SecureRecordLayer.h"

// 简易的十六进制打印工具
void PrintHex(const std::string& label, const CryptoModule::Bytes& data) {
    std::cout << label << " (len=" << data.size() << "): ";
    if (data.empty()) {
        std::cout << "[EMPTY]";
    } else {
        for (uint8_t byte : data) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
    }
    std::cout << std::dec << "\n";
}
// ==========================================
// 【新增】：为测试程序提供一个替身（Mock）函数，防止链接报错
// ==========================================
void BroadcastToMonitor(const std::string& event, const std::string& title, const std::string& details) {
    // 在纯终端的本地测试模式下，我们直接把大屏的数据打印到控制台即可
    std::cout << "\n========================================\n";
    std::cout << "[Mock Monitor - " << event << "] " << title << "\n";
    std::cout << details << "\n";
    std::cout << "========================================\n\n";
}
int main() {
    std::cout << "========================================================\n";
    std::cout << "  IoT 鲁棒多因子认证密钥协商协议 - 完整生命周期集成测试\n";
    std::cout << "========================================================\n\n";

    try {
        // 0. 初始化实体
        std::cout << "[初始化阶段]\n";
        Server gateway;
        //清理本地 SQLite 数据库中上一次测试的残留数据
        gateway.ClearDatabase();
        User alice("user_alice_001");
        std::string password = "StrongPassword123!";
        std::cout << " -> 网关服务器(Server)与用户终端(User)初始化完成.\n\n";

        // =========================================================
        // 阶段一：注册阶段 (Registration Phase)
        // =========================================================
        std::cout << "[注册阶段 (Registration Phase)]\n";
        
        // 用户录入高质量的初始生物特征
        CryptoModule::Bytes originalBio = BioModule::GenerateMockBiometric(64);
        std::cout << " 1. 用户端录入初始生物特征与口令.\n";

        // 用户生成注册包
        ProtocolMessages::RegistrationRequest regReq = alice.GenerateRegistrationRequest(password, originalBio);
        std::cout << " 2. 用户端生成注册包 (avk) 并发送给网关...\n";

        // 服务器处理注册包
        ProtocolMessages::RegistrationResponse regResp = gateway.ProcessRegistration(regReq);
        std::cout << " 3. 网关处理注册请求，成功存入数据库，返回长期公钥.\n";

        // 用户处理服务器响应
        alice.ProcessRegistrationResponse(regResp);
        std::cout << " 4. 用户端保存服务器公钥，完成本地凭证 (ask) 写入.\n\n";

        // =========================================================
        // 阶段二：认证与密钥协商阶段 (Authentication Phase)
        // =========================================================
        std::cout << "[认证与密钥协商阶段 (Authentication Phase)]\n";

        // 步骤 1: 客户端发起请求
        ProtocolMessages::AuthRequest authReq = alice.InitiateAuthentication();
        std::cout << " 步骤 1: 用户端向网关发起登录请求 (uid=" << authReq.uid << ").\n";

        // 步骤 2: 服务器生成挑战
        ProtocolMessages::AuthChallenge challenge = gateway.GenerateAuthChallenge(authReq.uid);
        std::cout << " 步骤 2: 网关生成临时DH公钥及签名，下发挑战包.\n";

        // 步骤 3: 客户端处理挑战并生成响应
        // 模拟用户再次按压指纹登录，带有 15 bit 的轻微合理误差 (小于容错阈值 50)
        CryptoModule::Bytes currentBio = BioModule::AddNoise(originalBio, 15);
        std::cout << " 步骤 3: 用户输入口令并按压指纹(附带真实物理噪声)...\n";
        
        ProtocolMessages::AuthResponse authResp = alice.ProcessAuthChallenge(challenge, password, currentBio);
        std::cout << "         用户端成功利用模糊提取器恢复密钥，验证网关签名，生成并加密响应包 (tau).\n";

        // 步骤 4: 服务器验证响应并生成最终确认
        ProtocolMessages::AuthConfirmation authConf = gateway.ProcessAuthResponse(authResp);
        std::cout << " 步骤 4: 网关解密载荷，验证用户签名，比对 tagU，下发最终确认 tagS.\n";

        // 步骤 5: 客户端进行最终确认
        bool isSuccess = alice.FinalizeAuthentication(authConf);
        std::cout << " 步骤 5: 用户端验证 tagS，认证流程结束.\n\n";

        // =========================================================
        // 验证结果
        // =========================================================
        std::cout << "[最终结果验证]\n";
        if (isSuccess) {
            std::cout << " -> 双向认证成功！\n";
            CryptoModule::Bytes clientSk = alice.GetSessionKey();
            CryptoModule::Bytes serverSk = gateway.GetSessionKey(authReq.uid);

            PrintHex(" -> 用户端最终会话密钥  ", clientSk);
            PrintHex(" -> 网关端最终会话密钥  ", serverSk);

            if (clientSk == serverSk && !clientSk.empty()) {
                std::cout << "\n >>> 恭喜！双方达成了完全一致的会话密钥，前向安全通道已建立！\n";
                // =========================================================
                // 阶段三：安全业务指令传输 (Secure Record Layer)
                // =========================================================
                std::cout << "\n========================================================\n";
                std::cout << "[阶段三：安全业务指令传输 (ChaCha20-Poly1305 AEAD)]\n";
                
                // 1. 实例化并初始化双方的安全记录层
                SecureRecordLayer clientRecordLayer;
                SecureRecordLayer serverRecordLayer;
                clientRecordLayer.Initialize(clientSk);
                serverRecordLayer.Initialize(serverSk);

                // 2. 用户端发送合法开锁指令
                std::string command = "{\"action\":\"unlock_door\", \"device\":\"front_door\"}";
                std::cout << " -> 用户端准备发送明文指令: " << command << "\n";

                // 调用封装，生成带 Length、Nonce、Tag 的跨平台二进制包
                CryptoModule::Bytes securePacket = clientRecordLayer.ProtectRecord(command);
                PrintHex(" -> 用户端发出加密封包 (TLV格式)", securePacket);

                // 3. 网关端接收并解密
                std::string decryptedCmd = serverRecordLayer.UnprotectRecord(securePacket);
                std::cout << " -> 网关端成功解密且通过完整性认证，执行指令: " << decryptedCmd << "\n";

                // 4. 【毕设高光演示】：模拟黑客重放攻击
                std::cout << "\n--------------------------------------------------------\n";
                std::cout << " [模拟攻击] 恶意黑客截获了刚才的加密封包，并在深夜尝试向网关重放...\n";
                try {
                    // 黑客将刚才截获的 securePacket 再次发送给服务器
                    serverRecordLayer.UnprotectRecord(securePacket); 
                    std::cout << " [漏洞] 警告：重放攻击成功！(如果看到此条说明防御失败)\n";
                } catch (const std::exception& e) {
                    // 预期的完美结果：底层抛出异常被我们捕获
                    std::cout << " -> [防御成功] 网关底层引擎直接切断连接！\n";
                    std::cout << " -> [拦截原因日志]: " << e.what() << "\n";
                }
                std::cout << "--------------------------------------------------------\n";
            } else {
                std::cout << "\n >>> 错误：双方会话密钥不一致！\n";
            }
        } else {
            std::cout << " -> 认证失败！\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "\n[致命错误] 协议执行异常中断: " << e.what() << "\n";
        return 1;
    }

    return 0;
}