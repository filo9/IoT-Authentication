#pragma once

#include <vector>
#include <cstdint>
#include <stdexcept>

namespace BCH {

    using Bytes = std::vector<uint8_t>;

    // =========================================================
    // 模块一：高维有限域 GF(2^10) 算术引擎
    // =========================================================
    class GaloisField {
    private:
        // 因为 2^10 = 1024，所以查表数组必须升级为 1024 长度，类型升级为 uint16_t
        uint16_t exp_table[1024]; 
        uint16_t log_table[1024]; 

    public:
        GaloisField();

        // GF(2) 的加减法本质依然是异或
        static inline uint16_t Add(uint16_t a, uint16_t b) { return a ^ b; }
        static inline uint16_t Sub(uint16_t a, uint16_t b) { return a ^ b; }

        uint16_t Mul(uint16_t a, uint16_t b) const;
        uint16_t Div(uint16_t a, uint16_t b) const;
        uint16_t Inv(uint16_t a) const;           
        uint16_t Power(uint16_t a, uint16_t n) const; 
    };

    // =========================================================
    // 模块二：高维多项式运算引擎 (系数升级为 uint16_t)
    // =========================================================
    class Polynomial {
    public:
        std::vector<uint16_t> coef; // coef[i] 代表 x^i 的系数

        Polynomial() {}
        Polynomial(const std::vector<uint16_t>& c) : coef(c) { Trim(); }

        void Trim();
        int Degree() const { return coef.empty() ? 0 : coef.size() - 1; }
        uint16_t Evaluate(uint16_t x, const GaloisField& gf) const;

        Polynomial Add(const Polynomial& other, const GaloisField& gf) const;
        Polynomial Multiply(const Polynomial& other, const GaloisField& gf) const;
        Polynomial Modulo(const Polynomial& divisor, const GaloisField& gf) const;
    };

    // =========================================================
    // 模块三：BCH(1023, 512) 编解码器主框架
    // =========================================================
    class BCHCodec {
    private:
        GaloisField gf;
        int n; // 码字总比特数 (1023)
        int k; // 信息比特数 (512)
        int t; // 纠错比特数 (51)
        Polynomial generator; 

        // 寻找特定根的最小多项式 (Cyclotomic Cosets)
        Polynomial ComputeMinimalPolynomial(int root_exponent) const;
        // 构建最终的生成多项式
        void BuildGenerator();

    public:
        BCHCodec(int n = 1023, int k = 512, int t = 51);

        std::vector<uint8_t> Encode(const std::vector<uint8_t>& message);
        std::vector<uint8_t> Decode(const std::vector<uint8_t>& received, bool& uncorrectable);
    };
} // namespace BCH

