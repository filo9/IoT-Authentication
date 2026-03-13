#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include "BioModule.h"

using namespace std;

// Mock 函数：防止链接器报错
void BroadcastToMonitor(const std::string& event, const std::string& title, const std::string& details) {}

BioModule::Bytes ReadDat(const string& path) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open()) { cerr << "❌ 找不到文件: " << path << endl; return {}; }
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    BioModule::Bytes buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

// 【核心修改】：计算比特 (Bit) 级差异，而非字节 (Byte) 级
int CalcBitDifference(const BioModule::Bytes& a, const BioModule::Bytes& b) {
    int diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        uint8_t xor_val = a[i] ^ b[i];
        while (xor_val) {
            diff += xor_val & 1; // 统计有多少个 bit 是 1
            xor_val >>= 1;
        }
    }
    return diff;
}

int main() {
    cout << "==================================================" << endl;
    cout << "🛡️ IoT Auth Protocol - BCH 比特级攻防测试" << endl;
    cout << "==================================================\n" << endl;

    auto bio_101_reg   = ReadDat("../fingerprint_features/101_1.dat"); 
    auto bio_101_auth  = ReadDat("../fingerprint_features/101_2.dat"); 
    auto bio_102_hacker= ReadDat("../fingerprint_features/102_1.dat"); 

    int diff_genuine = CalcBitDifference(bio_101_reg, bio_101_auth);
    int diff_impostor = CalcBitDifference(bio_101_reg, bio_102_hacker);
    
    cout << "📊 【比特级距离分析 (BCH(1023,512) 极限纠错: 51 Bits)】" << endl;
    cout << "🟢 合法用户 (101_1 vs 101_2) 差异比特数: " << diff_genuine << " / 512" << endl;
    cout << "🔴 冒充黑客 (101_1 vs 102_1) 差异比特数: " << diff_impostor << " / 512\n" << endl;

    cout << "⚙️ [系统] 正在为 User 101 生成安全草图 (Fuzzy Extractor Gen)..." << endl;
    auto feData = BioModule::Gen(bio_101_reg);
    cout << "✅ 提取完毕！生成的基准种子 R: ";
    for(int i=0; i<8; i++) printf("%02x", feData.R[i]); 
    cout << "...\n" << endl;

    cout << "🟢 [测试 1] 合法用户 101 发起登录..." << endl;
    auto R_recovered = BioModule::Rep(bio_101_auth, feData.P);
    if (!R_recovered.empty() && R_recovered == feData.R) {
        cout << "   ✅ 【测试通过】BCH 引擎雷达锁定并修复了 " << diff_genuine << " 个散落的比特物理坏点！" << endl;
    } else {
        cout << "   ❌ 【严重误拒 (FRR)】纠错失败！\n" << endl;
    }

    cout << "\n🔴 [测试 2] 黑客 102 尝试暴力冒充登录..." << endl;
    auto R_hacker = BioModule::Rep(bio_102_hacker, feData.P);
    if (R_hacker.empty()) {
        cout << "   ✅ 【防御成功】底层拦截生效！差异 " << diff_impostor << " 比特，彻底击穿纠错极限！" << endl;
        cout << "   🛡️ BioModule::Rep 已熔断，准备切入无感知欺骗模式生成伪造载荷。\n" << endl;
    } else {
        cout << "   💀 【致命误识 (FAR)】黑客指纹居然通过了纠错？！" << endl;
    }

    return 0;
}