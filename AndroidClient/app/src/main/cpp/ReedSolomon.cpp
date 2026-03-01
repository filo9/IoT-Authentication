#include "ReedSolomon.h"
#include <iostream>
#include <algorithm>

namespace RS {

    // =========================================================
    // 模块一：GF(2^8) 算术引擎实现
    // =========================================================
    GaloisField::GaloisField() {
        uint16_t primitive_poly = 0x11D; 
        uint8_t x = 1;
        for (int i = 0; i < 255; i++) {
            exp_table[i] = x;
            log_table[x] = i;
            if (x & 0x80) x = (x << 1) ^ (primitive_poly & 0xFF);
            else x <<= 1;
        }
        exp_table[255] = exp_table[0]; 
        log_table[0] = 0; 
    }

    uint8_t GaloisField::Mul(uint8_t a, uint8_t b) const {
        if (a == 0 || b == 0) return 0; 
        return exp_table[(log_table[a] + log_table[b]) % 255];
    }

    uint8_t GaloisField::Div(uint8_t a, uint8_t b) const {
        if (b == 0) throw std::invalid_argument("Division by zero");
        if (a == 0) return 0;
        return exp_table[(log_table[a] - log_table[b] + 255) % 255];
    }

    uint8_t GaloisField::Inv(uint8_t a) const {
        if (a == 0) throw std::invalid_argument("Zero has no inverse");
        return exp_table[255 - log_table[a]];
    }

    uint8_t GaloisField::Power(uint8_t a, uint8_t n) const {
        if (a == 0) return 0;
        if (n == 0) return 1;
        return exp_table[(log_table[a] * n) % 255];
    }

    // =========================================================
    // 模块二：多项式运算引擎实现
    // =========================================================
    void Polynomial::Trim() {
        while (coef.size() > 1 && coef.back() == 0) coef.pop_back();
        if (coef.empty()) coef.push_back(0);
    }

    uint8_t Polynomial::Evaluate(uint8_t x, const GaloisField& gf) const {
        if (x == 0) return coef.empty() ? 0 : coef[0];
        uint8_t result = 0;
        for (int i = coef.size() - 1; i >= 0; --i) {
            result = gf.Add(gf.Mul(result, x), coef[i]);
        }
        return result;
    }

    Polynomial Polynomial::Add(const Polynomial& other, const GaloisField& gf) const {
        Bytes result_coef(std::max(coef.size(), other.coef.size()), 0);
        for (size_t i = 0; i < coef.size(); ++i) result_coef[i] = coef[i];
        for (size_t i = 0; i < other.coef.size(); ++i) {
            result_coef[i] = gf.Add(result_coef[i], other.coef[i]);
        }
        return Polynomial(result_coef);
    }

    Polynomial Polynomial::Multiply(const Polynomial& other, const GaloisField& gf) const {
        if (coef.empty() || other.coef.empty()) return Polynomial(Bytes{0});
        Bytes result_coef(coef.size() + other.coef.size() - 1, 0);
        for (size_t i = 0; i < coef.size(); ++i) {
            if (coef[i] == 0) continue;
            for (size_t j = 0; j < other.coef.size(); ++j) {
                result_coef[i + j] = gf.Add(result_coef[i + j], gf.Mul(coef[i], other.coef[j]));
            }
        }
        return Polynomial(result_coef);
    }

    Polynomial Polynomial::Modulo(const Polynomial& divisor, const GaloisField& gf) const {
        Bytes rem = coef;
        Bytes div = divisor.coef;
        int rem_degree = rem.size() - 1;
        int div_degree = div.size() - 1;
        if (rem_degree < div_degree) return Polynomial(rem);

        for (int i = rem_degree; i >= div_degree; --i) {
            if (rem[i] == 0) continue;
            uint8_t factor = gf.Div(rem[i], div.back());
            for (size_t j = 0; j <= div_degree; ++j) {
                rem[i - div_degree + j] = gf.Sub(rem[i - div_degree + j], gf.Mul(div[j], factor));
            }
        }
        return Polynomial(rem);
    }

    // =========================================================
    // 模块三：RS 编解码器实现
    // =========================================================
    ReedSolomonCodec::ReedSolomonCodec(int n_val, int k_val) : n(n_val), k(k_val) {
        t = (n - k) / 2;
        BuildGenerator();
    }

    void ReedSolomonCodec::BuildGenerator() {
        generator = Polynomial(Bytes{1}); 
        for (int i = 1; i <= 2 * t; ++i) {
            Polynomial term(Bytes{gf.Power(2, i), 1});
            generator = generator.Multiply(term, gf);
        }
    }

    Bytes ReedSolomonCodec::Encode(const Bytes& message) {
        Bytes shifted_msg(2 * t, 0); 
        shifted_msg.insert(shifted_msg.end(), message.begin(), message.end());
        Polynomial msg_poly(shifted_msg);
        Polynomial remainder = msg_poly.Modulo(generator, gf);

        Bytes codeword = shifted_msg;
        for (size_t i = 0; i < remainder.coef.size(); ++i) {
            codeword[i] ^= remainder.coef[i];
        }
        return codeword; 
    }

    Polynomial ReedSolomonCodec::CalcSyndromes(const Polynomial& received, bool& has_error) const {
        Bytes syn(2 * t, 0);
        has_error = false;
        for (int i = 1; i <= 2 * t; ++i) {
            syn[i - 1] = received.Evaluate(gf.Power(2, i), gf);
            if (syn[i - 1] != 0) has_error = true;
        }
        return Polynomial(syn);
    }

    Polynomial ReedSolomonCodec::BerlekampMassey(const Polynomial& syndromes) const {
        Polynomial C(Bytes{1});  
        Polynomial B(Bytes{1});  
        int L = 0, m = 1;               
        uint8_t b = 1;           

        for (int i = 0; i < 2 * t; ++i) {
            uint8_t d = (i < syndromes.coef.size()) ? syndromes.coef[i] : 0;
            for (int j = 1; j <= L; ++j) {
                if (i - j >= 0 && j < C.coef.size()) {
                    uint8_t syn_val = (i - j < syndromes.coef.size()) ? syndromes.coef[i - j] : 0;
                    d = gf.Add(d, gf.Mul(C.coef[j], syn_val));
                }
            }
            if (d == 0) {
                m++;
            } else {
                Bytes term1_coef(m + 1, 0);
                term1_coef.back() = gf.Div(d, b); 
                Polynomial term1(term1_coef); 
                
                Polynomial T = C.Add(term1.Multiply(B, gf), gf);

                if (2 * L <= i) {
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
        return C;
    }

    std::vector<int> ReedSolomonCodec::ChienSearch(const Polynomial& err_locator) const {
        std::vector<int> err_pos;
        for (int i = 0; i < 255; ++i) {
            uint8_t root_candidate = gf.Inv(gf.Power(2, i));
            if (err_locator.Evaluate(root_candidate, gf) == 0) {
                err_pos.push_back(i);
            }
        }
        return err_pos;
    }

    Polynomial ReedSolomonCodec::Derivative(const Polynomial& poly) const {
        if (poly.coef.size() <= 1) return Polynomial(Bytes{0});
        Bytes deriv_coef(poly.coef.size() - 1, 0);
        for (size_t i = 1; i < poly.coef.size(); i += 2) {
            deriv_coef[i - 1] = poly.coef[i];
        }
        return Polynomial(deriv_coef);
    }

    Bytes ReedSolomonCodec::Forney(const Polynomial& received, const Polynomial& syndromes, 
                                   const Polynomial& err_locator, const std::vector<int>& err_pos) const {
        Polynomial omega = syndromes.Multiply(err_locator, gf);
        if (omega.coef.size() > 2 * t) omega.coef.resize(2 * t);
        omega.Trim();

        Polynomial err_locator_deriv = Derivative(err_locator);
        
        Bytes corrected = received.coef; 
        
        // 🔥 核心修复：把之前写死的 64 改为动态类成员 n，彻底拆除地雷！
        while(corrected.size() < n) corrected.push_back(0); 

        for (int pos : err_pos) {
            uint8_t x_inv = gf.Inv(gf.Power(2, pos));
            
            uint8_t num = omega.Evaluate(x_inv, gf);
            uint8_t den = err_locator_deriv.Evaluate(x_inv, gf);
            
            if (den == 0) throw std::runtime_error("Forney denominator is zero!");
            uint8_t err_magnitude = gf.Div(num, den);
            
            if (pos < corrected.size()) corrected[pos] ^= err_magnitude;
        }
        return corrected;
    }

    Bytes ReedSolomonCodec::Decode(const Bytes& received_bytes, bool& uncorrectable) {
        uncorrectable = false;
        Polynomial received(received_bytes);

        bool has_error = false;
        Polynomial syndromes = CalcSyndromes(received, has_error);
        if (!has_error) return Bytes(received_bytes.end() - k, received_bytes.end());

        try {
            Polynomial err_locator = BerlekampMassey(syndromes);
            std::vector<int> err_pos = ChienSearch(err_locator);
            
            if (err_pos.size() != err_locator.Degree()) {
                uncorrectable = true;
                return Bytes();
            }

            // 🔥 核心修复：把界限卡死在真正的 n 处，拦截幽灵错误
            for (int pos : err_pos) {
                if (pos >= n) { 
                    uncorrectable = true;
                    return Bytes();
                }
            }

            Bytes corrected = Forney(received, syndromes, err_locator, err_pos);
            return Bytes(corrected.end() - k, corrected.end());
        } catch (...) {
            uncorrectable = true;
            return Bytes();
        }
    }

} // namespace RS