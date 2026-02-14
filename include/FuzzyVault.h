#pragma once

#include <vector>
#include <cstdint>
#include <stdexcept>

namespace FV {

    // =========================================================
    // 模块一：16 维庞大有限域 GF(2^16) 算术引擎
    // =========================================================
    class GaloisField16 {
    private:
        // 2^16 = 65536，查表法占用 256KB 内存，换取极速的运算效率！
        uint16_t exp_table[65536];
        uint16_t log_table[65536];

    public:
        GaloisField16();

        // 域加法与减法依然是异或
        static inline uint16_t Add(uint16_t a, uint16_t b) { return a ^ b; }
        static inline uint16_t Sub(uint16_t a, uint16_t b) { return a ^ b; }

        uint16_t Mul(uint16_t a, uint16_t b) const;
        uint16_t Div(uint16_t a, uint16_t b) const;
        uint16_t Power(uint16_t a, uint16_t n) const;
        uint16_t Inv(uint16_t a) const;
    };

    // =========================================================
    // 模块二：多项式引擎 (追加拉格朗日所需运算)
    // =========================================================
    class Polynomial {
    public:
        std::vector<uint16_t> coef;

        Polynomial() {}
        Polynomial(const std::vector<uint16_t>& c) : coef(c) { Trim(); }

        void Trim();
        int Degree() const { return coef.empty() ? 0 : coef.size() - 1; }
        uint16_t Evaluate(uint16_t x, const GaloisField16& gf) const;
        
        Polynomial Add(const Polynomial& other, const GaloisField16& gf) const;
        Polynomial Multiply(const Polynomial& other, const GaloisField16& gf) const;
        
        // 【新增】：多项式标量乘法 (乘以一个常数)
        Polynomial Scale(uint16_t scalar, const GaloisField16& gf) const;
    };
    // =========================================================
    // 模块三：模糊金库核心引擎
    // =========================================================
    
    // 二维平面上的散点坐标 (X 为指纹特征，Y 为多项式求值)
    struct Point {
        uint16_t x;
        uint16_t y;
    };

    class VaultEngine {
    private:
        GaloisField16 gf;
        int k;          
        int num_chaff;  

        // 【新增】：拉格朗日插值算法核心
        Polynomial LagrangeInterpolate(const std::vector<Point>& points) const;

    public:
        VaultEngine(int k_val = 16, int chaff_val = 300);

        std::vector<Point> Lock(const std::vector<uint8_t>& key, const std::vector<uint16_t>& features);
        
        // 【新增】：解锁动作
        // 传入公开的金库 vault 和本次扫描的特征点 features_prime，尝试恢复密钥
        std::vector<uint8_t> Unlock(const std::vector<Point>& vault, const std::vector<uint16_t>& features_prime);
    };

} // namespace FV