#ifndef REED_SOLOMON_H
#define REED_SOLOMON_H

#include <vector>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace RS {

    using Bytes = std::vector<uint8_t>;

    // =========================================================
    // 模块一：有限域 GF(2^8) 算术引擎
    // =========================================================
    class GaloisField {
    private:
        uint8_t exp_table[256]; // 指数表：用于将加法转化为乘法
        uint8_t log_table[256]; // 对数表：用于将乘法转化为加法

    public:
        // 构造函数：基于本原多项式 x^8 + x^4 + x^3 + x^2 + 1 (0x11D) 初始化查表
        GaloisField();

        // 基础域运算重载 (加减法在特征为2的域中都是异或)
        static inline uint8_t Add(uint8_t a, uint8_t b) { return a ^ b; }
        static inline uint8_t Sub(uint8_t a, uint8_t b) { return a ^ b; }

        // 高级域运算
        uint8_t Mul(uint8_t a, uint8_t b) const;
        uint8_t Div(uint8_t a, uint8_t b) const;
        uint8_t Inv(uint8_t a) const;           // 求乘法逆元
        uint8_t Power(uint8_t a, uint8_t n) const; // 幂运算
    };

    // =========================================================
    // 模块二：有限域多项式运算引擎
    // =========================================================
    class Polynomial {
    public:
        Bytes coef; // 多项式的系数，coef[i] 代表 x^i 的系数

        Polynomial() {}
        Polynomial(const Bytes& c) : coef(c) { Trim(); }

        // 去除高位多余的 0
        void Trim();
        
        // 获取多项式的最高次幂 (度)
        int Degree() const { return coef.empty() ? 0 : coef.size() - 1; }
        
        // 多项式在 GF(2^8) 下的求值 (代入 x 计算结果)
        uint8_t Evaluate(uint8_t x, const GaloisField& gf) const;

        // 多项式基础运算
        Polynomial Add(const Polynomial& other, const GaloisField& gf) const;
        Polynomial Multiply(const Polynomial& other, const GaloisField& gf) const;
        // 多项式带余除法，返回余数 (用于计算校验位)
        Polynomial Modulo(const Polynomial& divisor, const GaloisField& gf) const;
    };

    // =========================================================
    // 模块三：RS(64, 32) 编解码器主框架
    // =========================================================
    class ReedSolomonCodec {
    private:
        GaloisField gf;
        int n; // 码字总长度 (64)
        int k; // 信息长度 (32)
        int t; // 纠错能力 (16)
        Polynomial generator; 

        void BuildGenerator();

        // 1. 计算伴随式 (Syndromes)
        Polynomial CalcSyndromes(const Polynomial& received, bool& has_error) const;
        // 2. Berlekamp-Massey 算法：求解错误位置多项式
        Polynomial BerlekampMassey(const Polynomial& syndromes) const;
        // 3. 钱氏搜索 (Chien Search)：寻找错误位置
        std::vector<int> ChienSearch(const Polynomial& err_locator) const;
        // 4. 福尼算法 (Forney Algorithm)：计算错误值并纠正
        Bytes Forney(const Polynomial& received, const Polynomial& syndromes, 
                     const Polynomial& err_locator, const std::vector<int>& err_pos) const;

        // 多项式求导 (用于福尼算法)
        Polynomial Derivative(const Polynomial& poly) const;

    public:
        ReedSolomonCodec(int n = 64, int k = 32);

        // 编码：输入 k 字节信息，返回 n 字节的码字 (信息 + 校验位)
        Bytes Encode(const Bytes& message);

        // 解码：输入带噪的 n 字节码字，返回修复后的 k 字节信息 (下一阶段实现)
        Bytes Decode(const Bytes& received, bool& uncorrectable);
    };
} // namespace RS

#endif // REED_SOLOMON_H