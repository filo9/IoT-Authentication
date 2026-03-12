#include <iostream>
#include <fstream>
#include <vector>
#include "BioModule.h"

using namespace std;
void BroadcastToMonitor(const string& event, const string& title, const string& details) {}

BioModule::Bytes ReadDat(const string& path) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open()) return {};
    streamsize size = file.tellg();
    file.seekg(0, ios::beg);
    BioModule::Bytes buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

int main() {
    cout << "==================================================" << endl;
    cout << "🏆 IoT Auth Protocol - 原生指纹图像模糊金库验证" << endl;
    cout << "==================================================\n" << endl;

    auto bio_101_reg   = ReadDat("../fingerprint_features/101_1.dat"); 
    auto bio_101_auth  = ReadDat("../fingerprint_features/101_2.dat"); 
    auto bio_102_hacker= ReadDat("../fingerprint_features/102_1.dat"); 

    cout << "⚙️ [系统] 正在为 User 101 生成 16次多项式安全草图..." << endl;
    auto feData = BioModule::Gen(bio_101_reg);
    cout << "✅ 提取完毕！生成的基准种子 R: ";
    for(int i=0; i<8; i++) printf("%02x", feData.R[i]); 
    cout << "...\n" << endl;

    cout << "🟢 [测试 1] 传入 101_2.tif 原生数据 (带有真实的平移/形变)..." << endl;
    auto R_recovered = BioModule::Rep(bio_101_auth, feData.P);
    if (!R_recovered.empty() && R_recovered == feData.R) {
        cout << "   ✅ 【验证成功】拉格朗日插值在网格化帮助下，完美跨越了原生特征的物理偏差！\n" << endl;
    } else {
        cout << "   ❌ 【错误拒识 (FRR)】重合点不足 16 个，解锁失败。\n" << endl;
    }

    cout << "🔴 [测试 2] 传入 102_1.tif 原生数据 (黑客冒充)..." << endl;
    auto R_hacker = BioModule::Rep(bio_102_hacker, feData.P);
    if (R_hacker.empty()) {
        cout << "   ✅ 【拦截成功】即使在模糊网格下，黑客指纹的重合点依然极其微小，被彻底熔断！" << endl;
    } else {
        cout << "   💀 【致命误识 (FAR)】黑客指纹居然通过了？！" << endl;
    }

    return 0;
}