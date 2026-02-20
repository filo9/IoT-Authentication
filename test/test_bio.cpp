#include <iostream>
#include <iomanip>
#include "BioModule.h"

// 辅助函数：将字节数组打印为十六进制字符串（方便观察 R 是否一致）
void PrintHex(const std::string& label, const BioModule::Bytes& data) {
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

int main() {
    std::cout << "=== IoT Auth Protocol: BioModule (Fuzzy Extractor) Test ===\n\n";

    try {
        // 1. 模拟注册阶段：用户首次录入生物特征
        std::cout << "[注册阶段 (Registration Phase)]\n";
        BioModule::Bytes originalBio = BioModule::GenerateMockBiometric(64); 
        std::cout << " -> 成功采集用户原始生物特征 (64 字节).\n";

        // 执行 Gen 函数，提取高熵随机串 R 和辅助数据 P
        BioModule::FuzzyExtractorData feData = BioModule::Gen(originalBio);
        std::cout << " -> Gen() 执行完毕.\n";
        PrintHex(" -> 提取的原始 R", feData.R);
        std::cout << " -> 生成的辅助数据 P 长度: " << feData.P.size() << " 字节 (公开存储).\n\n";


        // 2. 模拟认证阶段（成功案例）：用户正常按压指纹，产生轻微噪声
        std::cout << "[认证阶段 - 正常登录 (Expected: SUCCESS)]\n";
        int validNoiseBits = 20; // 注入 20 个错误比特 (小于阈值 50)
        std::cout << " -> 模拟采集登录特征 bio' (注入噪声: " << validNoiseBits << " bits)\n";
        BioModule::Bytes validNoisyBio = BioModule::AddNoise(originalBio, validNoiseBits);

        // 执行 Rep 函数，尝试纠错并恢复 R
        BioModule::Bytes recoveredR_Valid = BioModule::Rep(validNoisyBio, feData.P);
        PrintHex(" -> 恢复的 R'", recoveredR_Valid);

        if (recoveredR_Valid == feData.R && !recoveredR_Valid.empty()) {
            std::cout << " >>> 测试通过: 模糊提取器成功纠错，完美恢复了密钥种子 R！\n\n";
        } else {
            std::cout << " >>> 测试失败: 无法容忍设定的轻微噪声！\n\n";
        }


        // 3. 模拟认证阶段（失败案例）：攻击者使用错误的指纹尝试登录
        std::cout << "[认证阶段 - 攻击/错误指纹 (Expected: FAILURE)]\n";
        int invalidNoiseBits = 120; // 注入 120 个错误比特 (远超阈值 50)
        std::cout << " -> 模拟采集攻击者特征 bio_fake (注入差异: " << invalidNoiseBits << " bits)\n";
        BioModule::Bytes invalidNoisyBio = BioModule::AddNoise(originalBio, invalidNoiseBits);

        // 执行 Rep 函数，尝试恢复 R
        BioModule::Bytes recoveredR_Invalid = BioModule::Rep(invalidNoisyBio, feData.P);
        PrintHex(" -> 尝试恢复的 R'", recoveredR_Invalid);

        if (recoveredR_Invalid.empty()) {
            std::cout << " >>> 测试通过: 模糊提取器成功拦截了差异过大的非法生物特征，拒绝恢复 R！\n";
        } else {
            std::cout << " >>> 测试失败: 严重的安全漏洞！系统错误地接受了非法指纹！\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "\nException caught: " << e.what() << "\n";
        return 1;
    }

    return 0;
}