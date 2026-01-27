#include <iostream>
#include <iomanip>
#include "CryptoModule.h"

// 辅助函数：将字节数组打印为十六进制字符串
void PrintHex(const std::string& label, const CryptoModule::Bytes& data) {
    std::cout << label << " (len=" << data.size() << "): ";
    for (uint8_t byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << "\n"; // 恢复十进制打印
}

int main() {
    std::cout << "=== IoT Auth Protocol: CryptoModule Test ===\n\n";

    try {
        // 1. 测试哈希函数
        std::string rawData = "Hello IoT Gateway";
        CryptoModule::Bytes dataBytes(rawData.begin(), rawData.end());
        CryptoModule::Bytes hashResult = CryptoModule::Hash(dataBytes);
        PrintHex("1. SHA-256 Hash", hashResult);

        // 2. 测试 DH 密钥生成 (为前向安全性做准备)
        std::cout << "\n2. Generating Ephemeral DH Key Pairs...\n";
        CryptoModule::KeyPair aliceKeys = CryptoModule::GenerateDHKeyPair();
        CryptoModule::KeyPair bobKeys = CryptoModule::GenerateDHKeyPair();
        
        std::cout << "   Alice generates keys successfully.\n";
        std::cout << "   Bob generates keys successfully.\n";

        // 3. 测试 DH 共享秘密协商
        std::cout << "\n3. Computing Shared Secrets...\n";
        CryptoModule::Bytes aliceShared = CryptoModule::ComputeSharedSecret(aliceKeys.privateKey, bobKeys.publicKey);
        CryptoModule::Bytes bobShared = CryptoModule::ComputeSharedSecret(bobKeys.privateKey, aliceKeys.publicKey);

        PrintHex("   Alice's Shared Secret", aliceShared);
        PrintHex("   Bob's Shared Secret  ", bobShared);

        if (aliceShared == bobShared && !aliceShared.empty()) {
            std::cout << "\n>>> SUCCESS: DH Key Agreement matches! Forward Secrecy base is solid.\n";
        } else {
            std::cout << "\n>>> ERROR: DH Key Agreement failed!\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "\nException caught: " << e.what() << "\n";
        return 1;
    }

    return 0;
}