#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include "BioModuleV2.h"

using namespace std;

void BroadcastToMonitor(const string& event, const string& title, const string& details) {}

BioModuleV2::Bytes ReadDat(const string& path) {
    ifstream file(path, ios::binary | ios::ate);
    if (!file.is_open()) return {};
    streamsize size = file.tellg();
    if (size <= 0) return {};
    file.seekg(0, ios::beg);
    BioModuleV2::Bytes buffer(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

void Trim(string& s) {
    s.erase(remove_if(s.begin(), s.end(), [](unsigned char c){
        return c == '\r' || c == '\n' || c == ' ' || c == '"';
    }), s.end());
}

int main() {
    cout << "🏆 [V2] Fuzzy Vault 增强版压测引擎 (RS(64,32) t=16)..." << endl << endl;
    ifstream file("../unified_test_plan_vault.csv");
    if (!file.is_open()) { cerr << "❌ 找不到 ../unified_test_plan_vault.csv" << endl; return 1; }

    string line, type, template_name, probe_name, dummy;
    getline(file, line); // 表头

    int genuine_total = 0, genuine_accept = 0, impostor_total = 0, impostor_accept = 0;

    while (getline(file, line)) {
        stringstream ss(line);
        getline(ss, type, ',');
        getline(ss, template_name, ',');
        getline(ss, probe_name, ',');
        getline(ss, dummy, ',');

        Trim(type); Trim(template_name); Trim(probe_name);

        auto bio_template = ReadDat("../fingerprint_features/" + template_name + ".dat");
        auto bio_probe    = ReadDat("../fingerprint_features/" + probe_name + ".dat");

        if (bio_template.empty() || bio_probe.empty()) continue;

        auto feData     = BioModuleV2::Gen(bio_template);
        auto R_recovered = BioModuleV2::Rep(bio_probe, feData.P);
        bool accepted   = (!R_recovered.empty() && R_recovered == feData.R);

        if (type == "Genuine") { genuine_total++; if (accepted) genuine_accept++; }
        else                   { impostor_total++; if (accepted) impostor_accept++; }
    }

    double tar = (double)genuine_accept  / genuine_total  * 100.0;
    double frr = 100.0 - tar;
    double trr = (double)(impostor_total - impostor_accept) / impostor_total * 100.0;
    double far = 100.0 - trr;

    cout << "📊 【V2 RS(64,32) 增强版结果】" << endl;
    cout << "--------------------------------------------------" << endl;
    cout << "🟢 合法用户 (Genuine) 测试总数: " << genuine_total << " 次" << endl;
    cout << "   ✅ 成功验证 (TAR): " << genuine_accept << " 次 (" << fixed << setprecision(2) << tar << "%)" << endl;
    cout << "   ❌ 错误拒识 (FRR): " << genuine_total - genuine_accept << " 次 (" << frr << "%)" << endl;
    cout << "\n🔴 黑客冒充 (Impostor) 测试总数: " << impostor_total << " 次" << endl;
    cout << "   🛡️ 成功拦截 (TRR): " << impostor_total - impostor_accept << " 次 (" << trr << "%)" << endl;
    cout << "   💀 致命放行 (FAR): " << impostor_accept << " 次 (" << far << "%)" << endl;
    cout << "--------------------------------------------------" << endl;

    return 0;
}
