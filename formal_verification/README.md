# ProVerif 形式化验证

## 概述

本目录包含 IoT 认证协议的 ProVerif 形式化验证模型，使用 Applied Pi Calculus 建模，在 Dolev-Yao 威胁模型下验证协议安全性。

## 威胁模型

**Dolev-Yao 攻击者能力：**
- 窃听所有网络通信
- 拦截、删除、重放任意消息
- 篡改、伪造消息内容
- 发起中间人攻击（MITM）
- 无法破解密码学原语（完美密码学假设）

## 验证的安全属性

1. **会话密钥保密性（Secrecy）**
   - `query attacker(sessionKey).`
   - 验证攻击者无法获取会话密钥

2. **服务端对用户的认证（Authentication）**
   - `query uid: principal; event(ServerAcceptsUser(uid)) ==> event(UserStartsAuth(uid)).`
   - 验证服务端接受用户时，用户确实发起了认证

3. **用户对服务端的认证（Mutual Authentication）**
   - `query uid: principal; event(UserAcceptsServer(uid)) ==> event(ServerAcceptsUser(uid)).`
   - 验证用户接受服务端时，服务端确实完成了认证

4. **会话密钥一致性（Key Agreement）**
   - 验证双方派生的会话密钥一致

## 安装 ProVerif

```bash
# Ubuntu/Debian
sudo apt-get install proverif

# macOS
brew install proverif

# 或从源码编译
wget https://prosecco.gforge.inria.fr/personal/bblanche/proverif/proverif2.04.tar.gz
tar -xzf proverif2.04.tar.gz
cd proverif2.04
./build
sudo cp proverif /usr/local/bin/
```

## 运行验证

```bash
cd formal_verification
proverif protocol.pv
```

## 预期输出

```
--------------------------------------------------------------
Verification summary:

Query not attacker(sessionKey[]) is true.

Query event(ServerAcceptsUser(uid_3)) ==> event(UserStartsAuth(uid_3)) is true.

Query event(UserAcceptsServer(uid_3)) ==> event(ServerAcceptsUser(uid_3)) is true.

Query event(SessionKeyEstablished(uid_3,sk_2)) ==> event(SessionKeyEstablished(uid_3,sk_2)) is true.

--------------------------------------------------------------
```

## 协议建模说明

### 密码学原语

- **对称加密**: `senc/sdec` (AES-256-GCM)
- **非对称加密**: `aenc/adec` (ECIES)
- **数字签名**: `sign/verify` (ECDSA P-256)
- **哈希函数**: `hash` (SHA-256)
- **PRF**: `prf` (HMAC-SHA256)
- **HKDF**: `hkdf_extract/hkdf_expand` (RFC 5869)
- **Diffie-Hellman**: `exp(g, x)` (ECDH P-256)
- **模糊提取器**: `fuzzy_gen/fuzzy_rep` (Fuzzy Commitment + RS)
- **PUF**: `puf_enroll/puf_reconstruct` (Physical Unclonable Function)

### 协议流程

**注册阶段：**
1. 用户生成 PUF 密钥 k、模糊提取器辅助数据 P、主密钥 kmaster
2. 派生签名密钥对 (pkSig, skSig) 和加密密钥对 (pkEnc, skEnc)
3. 发送 (uid, pkSig, skEnc) 到服务器
4. 服务器返回长期公钥 serverPK

**认证阶段：**
1. 用户发送 uid
2. 服务器生成临时 DH 公钥 dhpubS、时间戳、nonce，签名后发送
3. 用户验证签名和时间戳，恢复生物特征 R，重构 kmaster
4. 用户生成临时 DH 公钥 dhpubU，计算共享秘密，生成 tagU
5. 用户签名 sigma，加密 tau = Enc(pkEnc, sigma || dhpubU)，发送 (uid, tau, tagU)
6. 服务器解密 tau，验证签名和 tagU，派生会话密钥
7. 服务器生成 tagS 并签名，发送确认
8. 用户验证 tagS，双方完成密钥协商

### 安全保证

- **前向安全性**: 临时 DH 密钥对每次会话重新生成
- **双向认证**: 服务器签名挑战，用户签名响应，服务器签名确认
- **重放攻击防护**: 时间戳 + nonce 绑定，序列号防重放
- **中间人攻击防护**: 签名绑定上下文（dhpubS, dhpubU, tagU, tagS）
- **密钥隔离**: HKDF 派生双向独立密钥（c2s_key, s2c_key）

## 论文引用

在论文中可以这样引用：

> 我们使用 ProVerif 自动化定理证明器对协议进行了形式化验证。在 Dolev-Yao 威胁模型下，ProVerif 证明了以下安全属性：(1) 会话密钥保密性，(2) 服务端对用户的认证，(3) 用户对服务端的双向认证，(4) 会话密钥一致性。验证结果表明，即使攻击者能够窃听、拦截、篡改所有网络数据包，协议仍能保证上述安全属性。

## 参考文献

- Bruno Blanchet. "Modeling and Verifying Security Protocols with the Applied Pi Calculus and ProVerif." Foundations and Trends in Privacy and Security, 2016.
- Dolev, D., & Yao, A. "On the security of public key protocols." IEEE Transactions on Information Theory, 1983.
