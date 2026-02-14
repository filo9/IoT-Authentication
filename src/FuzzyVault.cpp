#include "FuzzyVault.h"
#include <iostream>
#include <random>
#include <unordered_set>
#include <algorithm>
#include <numeric> // RANSAC 算法中 std::iota 需要用到

namespace FV {

    // =========================================================
    // GF(2^16) 初始化：生成 65535 个非零元素的对数与指数表
    // =========================================================
    GaloisField16::GaloisField16() {
        uint32_t primitive_poly = 0x1100B; 
        uint32_t x = 1;
        
        for (int i = 0; i < 65535; i++) {
            exp_table[i] = static_cast<uint16_t>(x);
            log_table[x] = static_cast<uint16_t>(i);
            x <<= 1;
            if (x & 0x10000) {
                x ^= primitive_poly;
            }
        }
        exp_table[65535] = exp_table[0]; 
        log_table[0] = 0; 
    }

    uint16_t GaloisField16::Mul(uint16_t a, uint16_t b) const {
        if (a == 0 || b == 0) return 0;
        return exp_table[(log_table[a] + log_table[b]) % 65535];
    }

    uint16_t GaloisField16::Div(uint16_t a, uint16_t b) const {
        if (b == 0) throw std::invalid_argument("FV::GaloisField16 Div by zero");
        if (a == 0) return 0;
        return exp_table[(log_table[a] - log_table[b] + 65535) % 65535];
    }

    uint16_t GaloisField16::Inv(uint16_t a) const {
        if (a == 0) throw std::invalid_argument("FV::GaloisField16 Zero has no inverse");
        return exp_table[65535 - log_table[a]];
    }

    uint16_t GaloisField16::Power(uint16_t a, uint16_t n) const {
        if (a == 0) return 0;
        if (n == 0) return 1;
        return exp_table[(static_cast<uint32_t>(log_table[a]) * n) % 65535];
    }

    // =========================================================
    // 多项式引擎实现
    // =========================================================
    void Polynomial::Trim() {
        while (coef.size() > 1 && coef.back() == 0) coef.pop_back();
        if (coef.empty()) coef.push_back(0);
    }

    uint16_t Polynomial::Evaluate(uint16_t x, const GaloisField16& gf) const {
        if (x == 0) return coef.empty() ? 0 : coef[0];
        uint16_t result = 0;
        for (int i = coef.size() - 1; i >= 0; --i) {
            result = gf.Add(gf.Mul(result, x), coef[i]);
        }
        return result;
    }

    Polynomial Polynomial::Add(const Polynomial& other, const GaloisField16& gf) const {
        std::vector<uint16_t> result_coef(std::max(coef.size(), other.coef.size()), 0);
        for (size_t i = 0; i < coef.size(); ++i) result_coef[i] = coef[i];
        for (size_t i = 0; i < other.coef.size(); ++i) {
            result_coef[i] = gf.Add(result_coef[i], other.coef[i]);
        }
        return Polynomial(result_coef);
    }

    Polynomial Polynomial::Multiply(const Polynomial& other, const GaloisField16& gf) const {
        if (coef.empty() || other.coef.empty()) return Polynomial({0});
        std::vector<uint16_t> result_coef(coef.size() + other.coef.size() - 1, 0);
        
        for (size_t i = 0; i < coef.size(); ++i) {
            if (coef[i] == 0) continue;
            for (size_t j = 0; j < other.coef.size(); ++j) {
                result_coef[i + j] = gf.Add(result_coef[i + j], gf.Mul(coef[i], other.coef[j]));
            }
        }
        return Polynomial(result_coef);
    }

    Polynomial Polynomial::Scale(uint16_t scalar, const GaloisField16& gf) const {
        if (scalar == 0 || coef.empty()) return Polynomial({0});
        std::vector<uint16_t> result(coef.size(), 0);
        for (size_t i = 0; i < coef.size(); ++i) {
            result[i] = gf.Mul(coef[i], scalar);
        }
        return Polynomial(result);
    }

    // =========================================================
    // 模块三：模糊金库引擎实现
    // =========================================================
    VaultEngine::VaultEngine(int k_val, int chaff_val) : k(k_val), num_chaff(chaff_val) {}

    std::vector<Point> VaultEngine::Lock(const std::vector<uint8_t>& key, const std::vector<uint16_t>& features) {
        if (key.size() != k * 2) {
            throw std::invalid_argument("FV::VaultEngine: 密钥长度必须严格匹配多项式系数空间的容量！");
        }

        std::vector<uint16_t> coeffs(k, 0);
        for (int i = 0; i < k; ++i) {
            coeffs[i] = (static_cast<uint16_t>(key[i * 2]) << 8) | key[i * 2 + 1];
        }
        Polynomial P(coeffs);

        std::vector<Point> vault;
        std::unordered_set<uint16_t> used_x; 

        // 注入真实特征点 (Genuine Points)
        for (uint16_t x : features) {
            if (used_x.find(x) != used_x.end()) continue; 
            used_x.insert(x);
            uint16_t y = P.Evaluate(x, gf);
            vault.push_back({x, y});
        }

        // 智能假点注入 (Smart Chaffing with Density Control)
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dis(1, 65535); 

        int chaff_added = 0;
        while (chaff_added < num_chaff) {
            uint16_t chaff_x = static_cast<uint16_t>(dis(gen));
            
            // 物理空间的距离排斥防御
            int cx = chaff_x >> 8;       
            int cy = chaff_x & 0xFF;     
            
            bool too_close = false;
            for (uint16_t used : used_x) {
                int ux = used >> 8;
                int uy = used & 0xFF;
                if ((cx - ux) * (cx - ux) + (cy - uy) * (cy - uy) <= 4) {
                    too_close = true;
                    break;
                }
            }
            if (too_close) continue; 
            
            uint16_t real_y = P.Evaluate(chaff_x, gf);
            uint16_t chaff_y;
            
            do {
                chaff_y = static_cast<uint16_t>(dis(gen));
            } while (chaff_y == real_y);

            used_x.insert(chaff_x);
            vault.push_back({chaff_x, chaff_y});
            chaff_added++;
        }

        std::shuffle(vault.begin(), vault.end(), gen);
        return vault;
    }

    Polynomial VaultEngine::LagrangeInterpolate(const std::vector<Point>& points) const {
        Polynomial P({0}); 
        
        for (size_t i = 0; i < points.size(); ++i) {
            Polynomial L_i({1}); 
            uint16_t den = 1;    
            
            for (size_t j = 0; j < points.size(); ++j) {
                if (i == j) continue;
                Polynomial term({points[j].x, 1}); 
                L_i = L_i.Multiply(term, gf);
                den = gf.Mul(den, gf.Sub(points[i].x, points[j].x));
            }
            
            uint16_t scalar = gf.Mul(points[i].y, gf.Inv(den));
            Polynomial scaled_L_i = L_i.Scale(scalar, gf);
            P = P.Add(scaled_L_i, gf);
        }
        return P;
    }

    // 金库解锁主逻辑 (引入 RANSAC 共识列表解码机制)
    std::vector<uint8_t> VaultEngine::Unlock(const std::vector<Point>& vault, const std::vector<uint16_t>& features_prime) {
        std::vector<Point> candidates;
        std::unordered_set<uint16_t> seen_x;

        // 1. 过滤碰撞 (大浪淘沙)
        for (uint16_t x_prime : features_prime) {
            if (seen_x.find(x_prime) != seen_x.end()) continue;
            for (const auto& v : vault) {
                if (v.x == x_prime) {
                    candidates.push_back(v);
                    seen_x.insert(x_prime); 
                    break; 
                }
            }
        }

        if (candidates.size() < k) {
            return std::vector<uint8_t>(); // 物理熔断：点数不够
        }

        // 2. 模拟 Guruswami-Sudan 列表解码的组合一致性搜索 (RANSAC)
        int max_consensus = -1;
        Polynomial best_poly({0});

        int n_cands = candidates.size();
        // 动态设定迭代次数：如果混入了假点，进行 50 次随机子集搜索寻找真相
        int iters = (n_cands > k) ? 50 : 1; 
        
        std::random_device rd;
        std::mt19937 gen(rd());

        for (int i = 0; i < iters; ++i) {
            std::vector<Point> subset(k);
            if (n_cands == k) {
                for(int j=0; j<k; ++j) subset[j] = candidates[j];
            } else {
                std::vector<int> indices(n_cands);
                std::iota(indices.begin(), indices.end(), 0);
                std::shuffle(indices.begin(), indices.end(), gen);
                for(int j=0; j<k; ++j) subset[j] = candidates[indices[j]];
            }

            Polynomial P = LagrangeInterpolate(subset);
            
            // 计算共识度 (Consensus): 这个多项式完美穿过了多少个候选点？
            int consensus = 0;
            for (const auto& pt : candidates) {
                if (P.Evaluate(pt.x, gf) == pt.y) consensus++;
            }
            
            if (consensus > max_consensus) {
                max_consensus = consensus;
                best_poly = P;
            }
            
            if (consensus >= n_cands || consensus > k + 2) break; 
        }

        if (max_consensus < k) return {};

        // 3. 将得票最高的真相系数打包成主密钥
        std::vector<uint8_t> recovered_key(k * 2, 0);
        for (int i = 0; i < k; ++i) {
            uint16_t c = (i < best_poly.coef.size()) ? best_poly.coef[i] : 0;
            recovered_key[i * 2] = static_cast<uint8_t>(c >> 8);
            recovered_key[i * 2 + 1] = static_cast<uint8_t>(c & 0xFF);
        }

        return recovered_key;
    }

} // namespace FV