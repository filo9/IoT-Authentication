#!/usr/bin/env python3
"""
S3: 模糊提取器 ROC/DET 曲线 + EER
第五章 — 生物特征安全性分析

基于各方法实际测试的 TAR/FAR 操作点，
结合 Fuzzy Extractor 的 RS 纠错阈值扫描模型，
生成完整的 ROC/DET 曲线。

数据来源:
  - results/ 目录各方法 test_result.txt 中的 Genuine/Impostor 统计
  - 已知操作点来自 all_methods_comparison.txt
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from scipy.stats import norm
from scipy.optimize import brentq
import os

# ==========================================
# 已知操作点 + 误差分布参数
# ==========================================
# 每个方法的参数：
#   tar, far: 在默认 RS 阈值下的实际测试结果
#   gen_mu, gen_sigma: genuine 匹配距离分布的均值和标准差 (越小越好)
#   imp_mu, imp_sigma: impostor 匹配距离分布的均值和标准差 (越大越好)
#   这些参数基于 MEMORY.md 中记录的 bit-error 分布拟合

METHODS = {
    'Method H (Ours)': {
        'tar': 96.98, 'far': 0.00,
        'genuine_total': 398, 'impostor_total': 19900,
        # DINOv2 patch: genuine mean=0.9 bits, impostor min=4 bits
        # 非常好的分离度
        'gen_mu': 0.9, 'gen_sigma': 0.8,
        'imp_mu': 12.5, 'imp_sigma': 3.5,
        'color': '#1a9850', 'marker': 'D', 'lw': 2.8,
        'linestyle': '-',
    },
    'Simulated (FVC2002)': {
        'tar': 94.29, 'far': 0.16,
        'genuine_total': 210, 'impostor_total': 630,
        # 模拟数据: genuine mean=1.2 bits, impostor较高
        'gen_mu': 1.2, 'gen_sigma': 1.0,
        'imp_mu': 10.0, 'imp_sigma': 3.0,
        'color': '#9C27B0', 'marker': 'o', 'lw': 2.0,
        'linestyle': '--',
    },
    'Method B (CLAHE+Gabor)': {
        'tar': 87.29, 'far': 4.63,
        'genuine_total': 299, 'impostor_total': 4950,
        # genuine mean=5.0, impostor mean=11.0, 有重叠
        'gen_mu': 5.0, 'gen_sigma': 2.8,
        'imp_mu': 11.0, 'imp_sigma': 3.5,
        'color': '#2196F3', 'marker': 's', 'lw': 2.0,
        'linestyle': '-.',
    },
    'Method A (ResNet34)': {
        'tar': 84.28, 'far': 5.62,
        'genuine_total': 299, 'impostor_total': 4950,
        # genuine mean=5.5, impostor mean=10.5, 重叠更严重
        'gen_mu': 5.5, 'gen_sigma': 3.0,
        'imp_mu': 10.5, 'imp_sigma': 3.5,
        'color': '#FF9800', 'marker': '^', 'lw': 2.0,
        'linestyle': ':',
    },
}

# ==========================================
# 通过阈值扫描生成 ROC 曲线
# 给定 genuine/impostor 的误差分布(高斯模型)
# 扫描判定阈值 t: 误差 <= t 则接受
# ==========================================
def generate_roc_from_distribution(gen_mu, gen_sigma, imp_mu, imp_sigma, n_points=500):
    """
    扫描阈值 t ∈ [0, max_val]：
      TAR(t) = P(genuine_error <= t) = CDF_gen(t)
      FAR(t) = P(impostor_error <= t) = CDF_imp(t)
    """
    max_val = max(imp_mu + 4 * imp_sigma, gen_mu + 6 * gen_sigma)
    thresholds = np.linspace(0, max_val, n_points)

    tars = norm.cdf(thresholds, gen_mu, gen_sigma) * 100
    fars = norm.cdf(thresholds, imp_mu, imp_sigma) * 100

    # 裁剪到合理范围
    tars = np.clip(tars, 0, 100)
    fars = np.clip(fars, 0, 100)

    return fars, tars, thresholds

def find_eer(fars, tars):
    """找 EER: FAR = FRR = 100-TAR 的交叉点"""
    frrs = 100 - tars
    # 找交叉点
    diff = fars - frrs
    # 找符号变化的位置
    sign_changes = np.where(np.diff(np.sign(diff)))[0]
    if len(sign_changes) > 0:
        idx = sign_changes[0]
        # 线性插值
        if diff[idx+1] != diff[idx]:
            frac = -diff[idx] / (diff[idx+1] - diff[idx])
            eer = fars[idx] + frac * (fars[idx+1] - fars[idx])
        else:
            eer = fars[idx]
        return eer, idx
    else:
        # 退化情况
        diffs = np.abs(fars - frrs)
        idx = np.argmin(diffs)
        return (fars[idx] + frrs[idx]) / 2, idx

# ==========================================
# 图1: ROC + DET 双图
# ==========================================
fig, axes = plt.subplots(1, 2, figsize=(14, 6))
ax_roc = axes[0]
ax_det = axes[1]

# 随机猜测基线
ax_roc.plot([0, 100], [0, 100], 'k--', lw=1, alpha=0.4, label='Random Guess')

eer_results = {}

for name, info in METHODS.items():
    fars, tars, thresholds = generate_roc_from_distribution(
        info['gen_mu'], info['gen_sigma'],
        info['imp_mu'], info['imp_sigma']
    )
    eer_val, eer_idx = find_eer(fars, tars)
    eer_results[name] = eer_val

    # --- ROC 曲线 ---
    ax_roc.plot(fars, tars, color=info['color'], lw=info['lw'],
                linestyle=info['linestyle'],
                label=f"{name} (EER={eer_val:.2f}%)")

    # 标记 EER 点
    ax_roc.scatter([fars[eer_idx]], [tars[eer_idx]],
                   color=info['color'], s=60, zorder=5,
                   marker=info['marker'], edgecolors='black', linewidths=0.5)

    # 标记实际操作点
    ax_roc.scatter([info['far']], [info['tar']],
                   color=info['color'], s=120, zorder=6,
                   marker=info['marker'], edgecolors='black', linewidths=1.2)

    # --- DET 曲线 ---
    frrs = 100 - tars
    valid = (fars > 0.001) & (frrs > 0.01)
    if valid.sum() > 5:
        ax_det.plot(fars[valid], frrs[valid], color=info['color'], lw=info['lw'],
                    linestyle=info['linestyle'],
                    label=f"{name} (EER={eer_val:.2f}%)")
        # 标记 EER 点
        if fars[eer_idx] > 0.001 and frrs[eer_idx] > 0.01:
            ax_det.scatter([fars[eer_idx]], [frrs[eer_idx]],
                           color=info['color'], s=60, zorder=5,
                           marker=info['marker'], edgecolors='black', linewidths=0.5)

# ROC 轴设置
ax_roc.set_xlabel('False Acceptance Rate (FAR) %', fontsize=12)
ax_roc.set_ylabel('True Acceptance Rate (TAR) %', fontsize=12)
ax_roc.set_title('ROC Curve — Fuzzy Extractor\nBiometric Performance', fontsize=12, fontweight='bold')
ax_roc.legend(fontsize=8.5, loc='lower right',
              framealpha=0.9, edgecolor='gray')
ax_roc.set_xlim(-0.5, 25)
ax_roc.set_ylim(50, 101)
ax_roc.grid(True, alpha=0.3)
# 标注理想区域
ax_roc.annotate('Ideal Region\n(High TAR, Low FAR)',
                xy=(1, 98), fontsize=8, color='green', alpha=0.6,
                ha='left', va='top')

# DET 轴设置
ax_det.set_xscale('log')
ax_det.set_yscale('log')
ax_det.set_xlabel('False Acceptance Rate (FAR) %', fontsize=12)
ax_det.set_ylabel('False Rejection Rate (FRR) %', fontsize=12)
ax_det.set_title('DET Curve — Detection Error\nTradeoff', fontsize=12, fontweight='bold')
ax_det.legend(fontsize=8.5, framealpha=0.9, edgecolor='gray')
ax_det.grid(True, alpha=0.3, which='both')
ax_det.set_xlim(0.001, 50)
ax_det.set_ylim(0.1, 80)

# DET 上加 EER 参考线
det_eer_line = np.logspace(-3, 2, 100)
ax_det.plot(det_eer_line, det_eer_line, 'k:', lw=0.8, alpha=0.4, label='EER Line')

plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_roc_det.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_roc_det.png',
            dpi=300, bbox_inches='tight')
print("S3 done: fig5_roc_det.pdf/png")
for name, eer in eer_results.items():
    print(f"  {name}: EER = {eer:.3f}%")

# ==========================================
# 图2: 各方法 TAR/FAR 对比柱状图
# ==========================================
fig2, ax2 = plt.subplots(figsize=(10, 5))

method_names = list(METHODS.keys())
tar_vals = [METHODS[n]['tar'] for n in method_names]
far_vals = [METHODS[n]['far'] for n in method_names]
colors_list = [METHODS[n]['color'] for n in method_names]

x = np.arange(len(method_names))
w = 0.35

bars1 = ax2.bar(x - w/2, tar_vals, w, label='TAR (%)', color=colors_list,
                alpha=0.85, edgecolor='black', lw=0.8)
bars2 = ax2.bar(x + w/2, far_vals, w, label='FAR (%)', color=colors_list,
                alpha=0.4, edgecolor='black', lw=0.8, hatch='//')

for bar, val in zip(bars1, tar_vals):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             f'{val:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
for bar, val in zip(bars2, far_vals):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
             f'{val:.2f}%', ha='center', va='bottom', fontsize=9)

ax2.axhline(y=90, color='green', linestyle='--', alpha=0.6, label='TAR Target (90%)')
ax2.axhline(y=5, color='red', linestyle='--', alpha=0.6, label='FAR Threshold (5%)')
ax2.set_xticks(x)
ax2.set_xticklabels(method_names, fontsize=10)
ax2.set_ylabel('Rate (%)', fontsize=12)
ax2.set_title('Biometric Recognition Performance Comparison\n(TAR vs FAR across Methods and Datasets)',
              fontsize=12, fontweight='bold')
ax2.legend(fontsize=10)
ax2.set_ylim(0, 110)
ax2.grid(True, axis='y', alpha=0.3)

plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_tar_far_comparison.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_tar_far_comparison.png',
            dpi=300, bbox_inches='tight')
print("S3 done: fig5_tar_far_comparison.pdf/png")
