#pragma once

#include "CryptoModule.h"

namespace DeterministicECC {

    /**
     * @brief 确定性椭圆曲线密钥推导接口 (Deterministic Key Derivation)
     * * 理论依据: (pk_Sig, sk_Sig) := KGen_S(pp; seed)
     * 该接口通过显式注入随机种子(seed)来生成 ECDSA 签名密钥对。
     * 在本协议中，seed 通常由 PRF 融合口令与生物特征得出 (即 K_master)。
     * * @param seed 高熵种子 (例如通过 H(K_master) 生成的 32 字节哈希值)
     * @return CryptoModule::KeyPair 包含确定性推导出的公钥和私钥
     */
    CryptoModule::KeyPair DeriveKeyPairFromSeed(const CryptoModule::Bytes& seed);

} // namespace DeterministicECC