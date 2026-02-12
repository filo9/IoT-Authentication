#include "BCHCodec.h"
#include <iostream>

namespace BCH {

    // =========================================================
    // 模块一：GF(2^10) 算术引擎实现
    // =========================================================
    GaloisField::GaloisField() {
        // 使用 GF(2^10) 的本原多项式: x^10 + x^3 + 1
        uint16_t primitive_poly = 0x409; 
        uint16_t x = 1;
        
        // 生成 1023 个非零元素的查表
        for (int i = 0; i < 1023; i++) {
            exp_table[i] = x;
            log_table[x] = i;
            x <<= 1;
            // 如果溢出了第 10 位 (即 >= 1024)，则异或本原多项式进行模运算
            if (x & 0x400) { 
                x ^= primitive_poly;
            }
        }
        // 循环封闭性
        exp_table[1023] = exp_table[0]; 
        log_table[0] = 0; // 0 没有对数
    }

    uint16_t GaloisField::Mul(uint16_t a, uint16_t b) const {
        if (a == 0 || b == 0) return 0; 
        // 模 1023，因为 GF(2^10) 有 1023 个非零元素
        return exp_table[(log_table[a] + log_table[b]) % 1023];
    }

    uint16_t GaloisField::Div(uint16_t a, uint16_t b) const {
        if (b == 0) throw std::invalid_argument("Division by zero");
        if (a == 0) return 0;
        return exp_table[(log_table[a] - log_table[b] + 1023) % 1023];
    }

    uint16_t GaloisField::Inv(uint16_t a) const {
        if (a == 0) throw std::invalid_argument("Zero has no inverse");
        return exp_table[1023 - log_table[a]];
    }

    uint16_t GaloisField::Power(uint16_t a, uint16_t n) const {
        if (a == 0) return 0;
        if (n == 0) return 1;
        return exp_table[(log_table[a] * n) % 1023];
    }
    // =========================================================
    // 模块二：多项式运算引擎实现
    // =========================================================
    void Polynomial::Trim() {
        while (coef.size() > 1 && coef.back() == 0) coef.pop_back();
        if (coef.empty()) coef.push_back(0);
    }

    uint16_t Polynomial::Evaluate(uint16_t x, const GaloisField& gf) const {
        if (x == 0) return coef.empty() ? 0 : coef[0];
        uint16_t result = 0;
        for (int i = coef.size() - 1; i >= 0; --i) {
            result = gf.Add(gf.Mul(result, x), coef[i]);
        }
        return result;
    }

    Polynomial Polynomial::Add(const Polynomial& other, const GaloisField& gf) const {
        std::vector<uint16_t> result_coef(std::max(coef.size(), other.coef.size()), 0);
        for (size_t i = 0; i < coef.size(); ++i) result_coef[i] = coef[i];
        for (size_t i = 0; i < other.coef.size(); ++i) {
            result_coef[i] = gf.Add(result_coef[i], other.coef[i]);
        }
        return Polynomial(result_coef);
    }

    Polynomial Polynomial::Multiply(const Polynomial& other, const GaloisField& gf) const {
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

    Polynomial Polynomial::Modulo(const Polynomial& divisor, const GaloisField& gf) const {
        std::vector<uint16_t> rem = coef;
        std::vector<uint16_t> div = divisor.coef;
        int rem_degree = rem.size() - 1;
        int div_degree = div.size() - 1;
        if (rem_degree < div_degree) return Polynomial(rem);

        for (int i = rem_degree; i >= div_degree; --i) {
            if (rem[i] == 0) continue;
            uint16_t factor = gf.Div(rem[i], div.back());
            for (size_t j = 0; j <= div_degree; ++j) {
                rem[i - div_degree + j] = gf.Sub(rem[i - div_degree + j], gf.Mul(div[j], factor));
            }
        }
        return Polynomial(rem);
    }

    // =========================================================
    // 模块三：BCH 生成多项式构建
    // =========================================================
    BCHCodec::BCHCodec(int n_val, int k_val, int t_val) : n(n_val), k(k_val), t(t_val) {
        BuildGenerator();
    }

    Polynomial BCHCodec::ComputeMinimalPolynomial(int root_exponent) const {
        // 寻找分圆陪集 (Cyclotomic Coset)
        std::vector<int> coset;
        int current = root_exponent;
        do {
            coset.push_back(current);
            current = (current * 2) % n; // 共轭根的指数是乘以 2
        } while (current != root_exponent);

        // 最小多项式 M(x) = (x - a^i1)(x - a^i2)...
        Polynomial min_poly({1}); // M(x) = 1
        for (int exp : coset) {
            // 构造 (x - a^exp)，注意在特征为 2 的域中减法就是加法，所以是 x + a^exp
            // 系数为：[a^exp, 1] 对应 a^exp * x^0 + 1 * x^1
            Polynomial term({gf.Power(2, exp), 1}); 
            min_poly = min_poly.Multiply(term, gf);
        }
        return min_poly;
    }

    void BCHCodec::BuildGenerator() {
        generator = Polynomial({1});
        std::vector<bool> visited(n, false);

        // 为了纠正 t 个错误，我们需要 2t 个连续的根：a^1, a^2, ..., a^2t
        for (int i = 1; i <= 2 * t; ++i) {
            if (visited[i]) continue; // 这个根已经在某个共轭陪集里算过了
            
            Polynomial min_poly = ComputeMinimalPolynomial(i);
            generator = generator.Multiply(min_poly, gf);

            // 标记这个陪集里的所有根为已访问
            int current = i;
            do {
                visited[current] = true;
                current = (current * 2) % n;
            } while (current != i);
        }
        
        // 极客断言：算出来的生成多项式系数必须全部是 0 或 1，否则数学模型崩溃！
        for (uint16_t c : generator.coef) {
            if (c != 0 && c != 1) {
                std::cerr << "CRITICAL ERROR: BCH Generator polynomial contains non-binary coefficients!" << std::endl;
            }
        }
        // generator 的度数必须等于 n - k，这由 BCH 码的信息论极限决定
    }

    // =========================================================
    // 模块四：BCH 比特级编码与解码引擎
    // =========================================================

    std::vector<uint8_t> BCHCodec::Encode(const std::vector<uint8_t>& message) {
        // 1. 将 64 字节 (512 bits) 的输入，完全打散为 512 个纯粹的比特位
        std::vector<uint8_t> msg_bits(k, 0);
        for(int i = 0; i < k; ++i) {
            msg_bits[i] = (message[i / 8] >> (7 - (i % 8))) & 1;
        }

        // 2. 构造系统码：将信息比特移至高位 [x^(n-k) * M(x)]
        std::vector<uint8_t> codeword_bits(n, 0);
        for(int i = 0; i < k; ++i) {
            codeword_bits[i + (n - k)] = msg_bits[i];
        }

        // 3. 多项式模二除法计算冗余校验位 (长除法)
        std::vector<uint8_t> rem = codeword_bits;
        int g_deg = generator.Degree(); // 必定为 n - k (511)
        for(int i = n - 1; i >= g_deg; --i) {
            if(rem[i] == 1) { // 如果最高位是 1，异或生成多项式
                for(int j = 0; j <= g_deg; ++j) {
                    rem[i - g_deg + j] ^= generator.coef[j]; 
                }
            }
        }

        // 4. 组装最终比特流：低 511 位是校验位，高 512 位是原始信息
        for(int i = 0; i < g_deg; ++i) {
            codeword_bits[i] = rem[i];
        }

        // 5. 将 1023 个比特重新打包回字节流 (128 Bytes，最后 1 bit 补零)
        std::vector<uint8_t> out((n + 7) / 8, 0);
        for(int i = 0; i < n; ++i) {
            if(codeword_bits[i]) {
                out[i / 8] |= (1 << (7 - (i % 8)));
            }
        }
        return out;
    }

    std::vector<uint8_t> BCHCodec::Decode(const std::vector<uint8_t>& received, bool& uncorrectable) {
        uncorrectable = false;

        // 1. 将 128 字节解包为 1023 个比特位
        std::vector<uint8_t> rec_bits(n, 0);
        for(int i = 0; i < n; ++i) {
            rec_bits[i] = (received[i / 8] >> (7 - (i % 8))) & 1;
        }

        // 2. 计算 2t 个伴随式 (Syndromes)：将 a^1 到 a^2t 代入接收多项式
        std::vector<uint16_t> syn(2 * t, 0);
        bool has_error = false;
        for(int j = 1; j <= 2 * t; ++j) {
            uint16_t root = gf.Power(2, j);
            uint16_t eval = 0;
            for(int i = n - 1; i >= 0; --i) {
                eval = gf.Add(gf.Mul(eval, root), rec_bits[i]);
            }
            syn[j - 1] = eval;
            if(eval != 0) has_error = true;
        }

        // 如果没有错误，直接截取高 512 位信息比特返回
        if(!has_error) {
            std::vector<uint8_t> out((k + 7) / 8, 0);
            for(int i = 0; i < k; ++i) {
                if(rec_bits[i + (n - k)]) out[i / 8] |= (1 << (7 - (i % 8)));
            }
            return out;
        }

        // 3. Berlekamp-Massey 算法：在 GF(2^10) 域上求解错误定位多项式
        Polynomial C({1});
        Polynomial B({1});
        int L = 0, m = 1;
        uint16_t b = 1;

        for(int i = 0; i < 2 * t; ++i) {
            uint16_t d = syn[i];
            for(int j = 1; j <= L; ++j) {
                if(j < C.coef.size()) d = gf.Add(d, gf.Mul(C.coef[j], syn[i - j]));
            }
            if(d == 0) {
                m++;
            } else {
                std::vector<uint16_t> term1_coef(m + 1, 0);
                term1_coef.back() = gf.Div(d, b);
                Polynomial term1(term1_coef);
                Polynomial T = C.Add(term1.Multiply(B, gf), gf);

                if(2 * L <= i) {
                    L = i + 1 - L;
                    B = C;
                    b = d;
                    m = 1;
                } else {
                    m++;
                }
                C = T;
            }
        }
        C.Trim();

        // 4. 钱氏搜索 (Chien Search)：遍历 1023 个位置寻找根
        std::vector<int> err_pos;
        for(int i = 0; i < n; ++i) {
            uint16_t root_candidate = gf.Inv(gf.Power(2, i));
            if(C.Evaluate(root_candidate, gf) == 0) {
                err_pos.push_back(i);
            }
        }

        // 错误数量超出纠错极限 (超过 51 个比特) -> 触发物理熔断！
        if(err_pos.size() != L) {
            uncorrectable = true;
            return std::vector<uint8_t>();
        }

        // 5. 见证奇迹的时刻：不需要 Forney，直接将错误比特就地反转！
        for(int pos : err_pos) {
            rec_bits[pos] ^= 1; 
        }

        // 6. 提取被完美修复的 64 字节信息
        std::vector<uint8_t> out((k + 7) / 8, 0);
        for(int i = 0; i < k; ++i) {
            if(rec_bits[i + (n - k)]) out[i / 8] |= (1 << (7 - (i % 8)));
        }
        return out;
    }
} // namespace BCH
