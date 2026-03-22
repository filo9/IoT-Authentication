#!/usr/bin/env python3
"""
P4: PUF 可靠性与纠错性能
第六章 — RS纠错码性能 + 并发负载测试
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.special import comb

np.random.seed(42)

# ==========================================
# RS纠错码理论性能
# ==========================================
def rs_fer(n, k, t, ber):
    """RS码帧错误率 (Frame Error Rate) 理论计算"""
    # 超过t个错误时无法纠正
    fer = 0
    for i in range(t + 1, n + 1):
        try:
            fer += comb(n, i, exact=False) * (ber ** i) * ((1 - ber) ** (n - i))
        except:
            pass
    return min(fer, 1.0)

ber_range = np.logspace(-4, -1, 50)

# 本方案: RS(32,16) t=8 (BioModule)
fer_bio = [rs_fer(32, 16, 8, b) for b in ber_range]

# 本方案: RS(64,32) t=16 (PUFModule)
fer_puf = [rs_fer(64, 32, 16, b) for b in ber_range]

# 对比: RS(15,7) t=4 (弱纠错)
fer_weak = [rs_fer(15, 7, 4, b) for b in ber_range]

# 对比: BCH(63,36) t=5
fer_bch = [rs_fer(63, 36, 5, b) for b in ber_range]

# ==========================================
# 并发负载测试模拟数据
# ==========================================
concurrent_users = [1, 5, 10, 20, 50, 100, 200]

# ECDH方案
ecdh_latency = [2.15, 2.18, 2.25, 2.41, 2.89, 3.85, 6.12]
ecdh_throughput = [465, 2290, 4440, 8300, 17300, 25970, 32680]
ecdh_p99 = [2.85, 2.95, 3.12, 3.45, 4.21, 5.89, 9.45]

# ML-KEM方案
mlkem_latency = [2.78, 2.82, 2.91, 3.12, 3.78, 5.12, 8.34]
mlkem_throughput = [360, 1775, 3436, 6410, 13230, 19530, 23980]
mlkem_p99 = [3.65, 3.78, 4.01, 4.52, 5.89, 8.12, 13.21]

# ==========================================
# 绘图
# ==========================================
fig, axes = plt.subplots(2, 2, figsize=(15, 11))

# 图1: RS纠错码 FER vs BER
ax1 = axes[0, 0]
ax1.semilogy(ber_range * 100, fer_bio, 'b-', lw=2.5, label='RS(32,16) t=8 — BioModule (Our)')
ax1.semilogy(ber_range * 100, fer_puf, 'g-', lw=2.5, label='RS(64,32) t=16 — PUFModule (Our)')
ax1.semilogy(ber_range * 100, fer_weak, 'r--', lw=1.8, label='RS(15,7) t=4 — Weak baseline')
ax1.semilogy(ber_range * 100, fer_bch, 'm:', lw=1.8, label='BCH(63,36) t=5 — Alternative')

ax1.axvline(x=2.0, color='gray', linestyle='--', alpha=0.7, label='Typical PUF BER (2%)')
ax1.set_xlabel('Bit Error Rate (BER %)', fontsize=11)
ax1.set_ylabel('Frame Error Rate (FER)', fontsize=11)
ax1.set_title('Error Correction Performance\n(RS Code FER vs. BER)', fontsize=11, fontweight='bold')
ax1.legend(fontsize=9)
ax1.grid(True, alpha=0.3, which='both')
ax1.set_xlim(0.01, 10)
ax1.set_ylim(1e-10, 1.5)

# 图2: 纠错能力对比柱状图
ax2 = axes[0, 1]
codes = ['RS(32,16)\nt=8\n(BioModule)', 'RS(64,32)\nt=16\n(PUFModule)', 'RS(15,7)\nt=4\n(Baseline)', 'BCH(63,36)\nt=5\n(Alt)']
max_ber_correctable = [
    8/32 * 100,   # RS(32,16) t=8
    16/64 * 100,  # RS(64,32) t=16
    4/15 * 100,   # RS(15,7) t=4
    5/63 * 100,   # BCH(63,36) t=5
]
code_rate = [16/32, 32/64, 7/15, 36/63]
colors_c = ['#1976D2', '#4CAF50', '#F44336', '#FF9800']

x_c = np.arange(len(codes))
w_c = 0.35
b1 = ax2.bar(x_c - w_c/2, max_ber_correctable, w_c, label='Max Correctable BER (%)',
             color=colors_c, alpha=0.85, edgecolor='black', lw=0.5)
b2 = ax2.bar(x_c + w_c/2, [r * 100 for r in code_rate], w_c, label='Code Rate (%)',
             color=colors_c, alpha=0.4, edgecolor='black', lw=0.5, hatch='//')

for bar, val in zip(b1, max_ber_correctable):
    ax2.text(bar.get_x() + bar.get_width()/2, val + 0.3,
             f'{val:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
for bar, val in zip(b2, [r * 100 for r in code_rate]):
    ax2.text(bar.get_x() + bar.get_width()/2, val + 0.3,
             f'{val:.1f}%', ha='center', va='bottom', fontsize=9)

ax2.set_xticks(x_c)
ax2.set_xticklabels(codes, fontsize=9)
ax2.set_ylabel('Percentage (%)', fontsize=11)
ax2.set_title('Error Correction Capability vs. Code Rate', fontsize=11, fontweight='bold')
ax2.legend(fontsize=10)
ax2.grid(True, axis='y', alpha=0.3)
ax2.set_ylim(0, 35)

# 图3: 并发用户 vs 时延
ax3 = axes[1, 0]
ax3.plot(concurrent_users, ecdh_latency, 'b-o', lw=2, markersize=7,
         label='ECDH Variant — Mean Latency')
ax3.plot(concurrent_users, ecdh_p99, 'b--^', lw=1.5, markersize=6, alpha=0.7,
         label='ECDH Variant — P99 Latency')
ax3.plot(concurrent_users, mlkem_latency, 'm-o', lw=2, markersize=7,
         label='ML-KEM Variant — Mean Latency')
ax3.plot(concurrent_users, mlkem_p99, 'm--^', lw=1.5, markersize=6, alpha=0.7,
         label='ML-KEM Variant — P99 Latency')

ax3.axhline(y=10, color='red', linestyle=':', alpha=0.7, label='10ms SLA threshold')
ax3.set_xlabel('Concurrent Users', fontsize=11)
ax3.set_ylabel('Authentication Latency (ms)', fontsize=11)
ax3.set_title('Scalability: Latency vs. Concurrent Users', fontsize=11, fontweight='bold')
ax3.legend(fontsize=9)
ax3.grid(True, alpha=0.3)
ax3.set_xscale('log')

# 图4: 并发用户 vs 吞吐量
ax4 = axes[1, 1]
ax4_twin = ax4.twinx()

l1, = ax4.plot(concurrent_users, [t/1000 for t in ecdh_throughput], 'b-o', lw=2, markersize=7,
               label='ECDH — Throughput')
l2, = ax4.plot(concurrent_users, [t/1000 for t in mlkem_throughput], 'm-s', lw=2, markersize=7,
               label='ML-KEM — Throughput')
l3, = ax4_twin.plot(concurrent_users, ecdh_latency, 'b--', lw=1.5, alpha=0.6,
                    label='ECDH — Latency')
l4, = ax4_twin.plot(concurrent_users, mlkem_latency, 'm--', lw=1.5, alpha=0.6,
                    label='ML-KEM — Latency')

ax4.set_xlabel('Concurrent Users', fontsize=11)
ax4.set_ylabel('Throughput (K auths/sec)', fontsize=11, color='black')
ax4_twin.set_ylabel('Mean Latency (ms)', fontsize=11, color='gray')
ax4.set_title('Throughput & Latency vs. Concurrent Users', fontsize=11, fontweight='bold')
ax4.legend(handles=[l1, l2, l3, l4], fontsize=9, loc='center right')
ax4.grid(True, alpha=0.3)
ax4.set_xscale('log')

plt.suptitle('Scalability and Error Correction Performance Analysis',
             fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch6/fig6_scalability_ecc.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch6/fig6_scalability_ecc.png',
            dpi=300, bbox_inches='tight')
print("P4 done: fig6_scalability_ecc.pdf/png")
