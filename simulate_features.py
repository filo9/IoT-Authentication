import os
import numpy as np
import csv

OUTPUT_DIR = "./fingerprint_features"
os.makedirs(OUTPUT_DIR, exist_ok=True)

mapped_users = [str(i) for i in range(101, 111)]
samples = range(1, 7)

print("🧠 启动端到端神经密码学[纯数学模拟引擎]...")

# 设定随机种子，保证每次生成的数据完全一样，方便你写论文做对比
np.random.seed(42) 
processed_files = 0

# =========================================================
# 🎛️ 核心调节旋钮：物理噪声水平 (Noise Level)
# 0.0 = 完全没有形变 (TAR 100%)
# 0.4 = 模拟真实的优秀指纹传感器环境 (TAR 极高)
# 0.8 = 模拟极度恶劣、手指脱皮、大量汗液的环境 (考验 RS 极限)
# =========================================================
NOISE_SIGMA = 0.4

for u in mapped_users:
    # 1. 模板(Template)：用正态分布凭空捏造该用户独一无二的 512 维“理想特征”
    base_feature = np.random.randn(512).astype(np.float32)
    
    # 强制零均值化，完美匹配 C++ 中 '>0' 的二值化密码学象限
    base_feature = base_feature - np.mean(base_feature)

    for i in samples:
        if i == 1:
            feat = base_feature
        else:
            # 2. 探针(Probe)：向完美特征中注入随机的高斯白噪声
            noise = np.random.randn(512).astype(np.float32) * NOISE_SIGMA
            feat = base_feature + noise
            feat = feat - np.mean(feat) # 保持探针也是零均值

        # 将 512 个 float 写入二进制文件 (恰好 2048 Bytes)
        with open(os.path.join(OUTPUT_DIR, f"{u}_{i}_vault.dat"), "wb") as f:
            f.write(feat.tobytes())
        processed_files += 1

print(f"✅ 模拟神经特征生成完毕！(噪声方差: {NOISE_SIGMA})")

# 生成压测专用的 CSV 计划表
test_plan_vault = []
for u in mapped_users:
    for i in samples:
        for j in range(i + 1, 7):
            test_plan_vault.append(["Genuine", f"{u}_{i}_vault", f"{u}_{j}_vault", 0])
for u1 in mapped_users:
    for i in samples:
        for u2 in mapped_users:
            if u1 == u2: continue
            test_plan_vault.append(["Impostor", f"{u1}_{i}_vault", f"{u2}_1_vault", 0])

with open("unified_test_plan_vault.csv", "w", newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["Type", "Template", "Probe", "ErrorBits"])
    writer.writerows(test_plan_vault)
print("👉 下一步：切换到 build 目录直接运行 ./test_batch_vault 见证奇迹！")