#!/usr/bin/env python3
"""
S4: PUF 安全性分析
第五章 — 可靠性、唯一性、随机性
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy import stats

np.random.seed(42)

N_DEVICES = 200
N_CHALLENGES = 50
RESPONSE_BITS = 512

# ==========================================
# 模拟 SRAM PUF 响应
# ==========================================
def simulate_puf_response(device_id, challenge_id, bits=RESPONSE_BITS):
    """模拟SRAM PUF：每个设备有固定的"理想"响应，加上制造噪声"""
    rng = np.random.default_rng(hash(f"dev{device_id}_ch{challenge_id}") & 0xFFFFFFFF)
    return rng.integers(0, 2, bits, dtype=np.uint8)

def add_measurement_noise(response, ber=0.02):
    """模拟测量噪声（温度/电压波动）"""
    noisy = response.copy()
    flip_mask = np.random.random(len(response)) < ber
    noisy[flip_mask] = 1 - noisy[flip_mask]
    return noisy

def hamming_distance(a, b):
    return np.sum(a != b) / len(a) * 100  # 百分比

# ==========================================
# 1. 可靠性测试：同设备同challenge多次测量
# ==========================================
print("计算可靠性...")
reliability_bhds = []
ber_levels = np.linspace(0, 0.08, 25)
reliability_by_ber = []

for ber in ber_levels:
    bhds = []
    for dev in range(N_DEVICES):
        ref = simulate_puf_response(dev, 0)
        for trial in range(20):
            noisy = add_measurement_noise(ref, ber)
            bhds.append(hamming_distance(ref, noisy))
    reliability_by_ber.append(np.mean(bhds))

# 固定BER=0.02的分布
bhds_fixed = []
for dev in range(N_DEVICES):
    ref = simulate_puf_response(dev, 0)
    for trial in range(N_CHALLENGES):
        noisy = add_measurement_noise(ref, 0.02)
        bhds_fixed.append(hamming_distance(ref, noisy))

# ==========================================
# 2. 唯一性测试：不同设备间BHD
# ==========================================
print("计算唯一性...")
uniqueness_bhds = []
responses = [simulate_puf_response(d, 0) for d in range(N_DEVICES)]
for i in range(0, N_DEVICES, 2):
    for j in range(i+1, min(i+20, N_DEVICES)):
        uniqueness_bhds.append(hamming_distance(responses[i], responses[j]))

# ==========================================
# 3. 随机性测试：比特分布
# ==========================================
print("计算随机性...")
all_bits = np.concatenate([simulate_puf_response(d, c)
                           for d in range(50) for c in range(10)])
ones_ratio = np.mean(all_bits) * 100

# ==========================================
# 绘图
# ==========================================
fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# 图1: 可靠性 vs BER
ax1 = axes[0, 0]
ax1.plot(ber_levels * 100, reliability_by_ber, 'b-o', markersize=5, lw=2, label='Mean BHD')
ax1.axhline(y=3.125, color='r', linestyle='--', lw=1.5,
            label=f'RS(64,32) correction limit (t=16, {16/512*100:.1f}%)')
ax1.fill_between(ber_levels * 100, 0, 3.125, alpha=0.1, color='green', label='Correctable zone')
ax1.set_xlabel('Physical Noise Level (BER %)', fontsize=12)
ax1.set_ylabel('Mean Bit Hamming Distance (%)', fontsize=12)
ax1.set_title('PUF Reliability vs. Noise Level', fontsize=12, fontweight='bold')
ax1.legend(fontsize=10)
ax1.grid(True, alpha=0.3)
ax1.set_xlim(0, 8)
ax1.set_ylim(0, 10)

# 图2: 可靠性BHD分布直方图（BER=2%）
ax2 = axes[0, 1]
ax2.hist(bhds_fixed, bins=30, color='#2196F3', alpha=0.8, edgecolor='black', lw=0.5)
mu, sigma = np.mean(bhds_fixed), np.std(bhds_fixed)
ax2.axvline(mu, color='red', lw=2, linestyle='--', label=f'Mean={mu:.2f}%')
ax2.axvline(mu + 2*sigma, color='orange', lw=1.5, linestyle=':', label=f'μ+2σ={mu+2*sigma:.2f}%')
ax2.axvline(3.125, color='green', lw=2, linestyle='-.',
            label='RS correction limit (3.125%)')
ax2.set_xlabel('Bit Hamming Distance (%)', fontsize=12)
ax2.set_ylabel('Frequency', fontsize=12)
ax2.set_title(f'Reliability BHD Distribution (BER=2%, N={len(bhds_fixed)})',
              fontsize=12, fontweight='bold')
ax2.legend(fontsize=9)
ax2.grid(True, alpha=0.3)

# 图3: 唯一性BHD分布
ax3 = axes[1, 0]
ax3.hist(uniqueness_bhds, bins=35, color='#4CAF50', alpha=0.8, edgecolor='black', lw=0.5)
mu_u, sigma_u = np.mean(uniqueness_bhds), np.std(uniqueness_bhds)
ax3.axvline(mu_u, color='red', lw=2, linestyle='--', label=f'Mean={mu_u:.2f}%')
ax3.axvline(50, color='blue', lw=2, linestyle=':', label='Ideal (50%)')
x_norm = np.linspace(30, 70, 200)
y_norm = stats.norm.pdf(x_norm, mu_u, sigma_u) * len(uniqueness_bhds) * (uniqueness_bhds[1] - uniqueness_bhds[0] if len(uniqueness_bhds) > 1 else 1)
ax3.set_xlabel('Inter-Device Bit Hamming Distance (%)', fontsize=12)
ax3.set_ylabel('Frequency', fontsize=12)
ax3.set_title(f'PUF Uniqueness Distribution (N={len(uniqueness_bhds)} pairs)',
              fontsize=12, fontweight='bold')
ax3.legend(fontsize=10)
ax3.grid(True, alpha=0.3)

# 图4: 随机性 — 比特频率分布
ax4 = axes[1, 1]
# 按设备统计每个设备的1比特占比
per_device_ones = []
for d in range(N_DEVICES):
    resp = simulate_puf_response(d, 0)
    per_device_ones.append(np.mean(resp) * 100)

ax4.hist(per_device_ones, bins=25, color='#FF9800', alpha=0.8, edgecolor='black', lw=0.5)
ax4.axvline(50, color='blue', lw=2, linestyle='--', label='Ideal (50%)')
ax4.axvline(np.mean(per_device_ones), color='red', lw=2, linestyle='-.',
            label=f'Mean={np.mean(per_device_ones):.2f}%')
ax4.set_xlabel("Proportion of '1' Bits (%)", fontsize=12)
ax4.set_ylabel('Number of Devices', fontsize=12)
ax4.set_title(f'PUF Randomness — Bit Distribution\n(N={N_DEVICES} devices, {RESPONSE_BITS} bits each)',
              fontsize=12, fontweight='bold')
ax4.legend(fontsize=10)
ax4.grid(True, alpha=0.3)

# 统计摘要文字
summary = (f"Reliability: μ={mu:.2f}%, σ={sigma:.2f}%\n"
           f"Uniqueness:  μ={mu_u:.2f}%, σ={sigma_u:.2f}%\n"
           f"Randomness:  {ones_ratio:.2f}% ones (ideal: 50%)")
fig.text(0.5, 0.01, summary, ha='center', fontsize=11,
         bbox=dict(boxstyle='round', facecolor='lightyellow', alpha=0.8))

plt.suptitle('PUF Security Analysis: Reliability, Uniqueness, and Randomness',
             fontsize=14, fontweight='bold', y=1.01)
plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_puf_analysis.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_puf_analysis.png',
            dpi=300, bbox_inches='tight')
print(f"S4 done: fig5_puf_analysis.pdf/png")
print(f"  Reliability: mean={mu:.3f}%, std={sigma:.3f}%")
print(f"  Uniqueness:  mean={mu_u:.3f}%, std={sigma_u:.3f}%")
print(f"  Randomness:  {ones_ratio:.2f}% ones")
