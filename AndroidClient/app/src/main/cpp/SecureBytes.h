#ifndef SECURE_BYTES_H
#define SECURE_BYTES_H

#include <vector>
#include <cstdint>
#include <openssl/crypto.h>

// ==========================================
// SecureBytes: 自动安全擦除的字节数组
// ==========================================
// 用于存储敏感数据（密钥、密码、共享秘密等）
// 析构时自动调用 OPENSSL_cleanse 安全擦除内存
// 防止敏感数据在内存中残留被攻击者读取
class SecureBytes : public std::vector<uint8_t> {
public:
    // 继承所有 vector 的构造函数
    using std::vector<uint8_t>::vector;

    // 默认构造函数
    SecureBytes() : std::vector<uint8_t>() {}

    // 从普通 vector 构造
    SecureBytes(const std::vector<uint8_t>& other) : std::vector<uint8_t>(other) {}

    // 移动构造
    SecureBytes(std::vector<uint8_t>&& other) noexcept : std::vector<uint8_t>(std::move(other)) {}

    // 拷贝构造
    SecureBytes(const SecureBytes& other) : std::vector<uint8_t>(other) {}

    // 移动构造
    SecureBytes(SecureBytes&& other) noexcept : std::vector<uint8_t>(std::move(other)) {}

    // 拷贝赋值
    SecureBytes& operator=(const SecureBytes& other) {
        if (this != &other) {
            // 先擦除当前内容
            if (!this->empty()) {
                OPENSSL_cleanse(this->data(), this->size());
            }
            std::vector<uint8_t>::operator=(other);
        }
        return *this;
    }

    // 移动赋值
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            // 先擦除当前内容
            if (!this->empty()) {
                OPENSSL_cleanse(this->data(), this->size());
            }
            std::vector<uint8_t>::operator=(std::move(other));
        }
        return *this;
    }

    // 从普通 vector 赋值
    SecureBytes& operator=(const std::vector<uint8_t>& other) {
        if (!this->empty()) {
            OPENSSL_cleanse(this->data(), this->size());
        }
        std::vector<uint8_t>::operator=(other);
        return *this;
    }

    // 析构函数：安全擦除内存
    ~SecureBytes() {
        if (!this->empty()) {
            OPENSSL_cleanse(this->data(), this->size());
        }
    }

    // 显式清除方法（可在析构前手动调用）
    void secure_clear() {
        if (!this->empty()) {
            OPENSSL_cleanse(this->data(), this->size());
        }
        this->clear();
    }
};

#endif // SECURE_BYTES_H
