#!/usr/bin/env python3
"""
P3: 通信开销对比图
第六章 — 各协议步骤消息大小分析
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# ==========================================
# 消息大小数据 (bytes)
# ==========================================

# 本方案 ECDH 各步骤消息大小
ecdh_messages = {
    'Step1\nAuth Request':    {'uid': 16, 'other': 0},
    'Step2\nChallenge':       {'dhpubS': 65, 'serversigm': 72, 'timestamp': 8, 'nonce': 16},
    'Step3\nAuth Response':   {'tau_sigma': 72, 'tau_dhpubU': 65, 'tau_enc_overhead': 28, 'tagU': 32},
    'Step4\nConfirmation':    {'tagS': 32, 'serversigtag': 72},
}

# 本方案 ML-KEM 各步骤消息大小
mlkem_messages = {
    'Step1\nAuth Request':    {'uid': 16, 'other': 0},
    'Step2\nChallenge':       {'pkKEM': 1184, 'serversigm': 72, 'timestamp': 8, 'nonce': 16},
    'Step3\nAuth Response':   {'tau_sigma': 72, 'tau_ct': 1088, 'tau_enc_overhead': 28, 'tagU': 32},
    'Step4\nConfirmation':    {'tagS': 32, 'serversigtag': 72},
}

# 注册消息
reg_ecdh = {'pkSig': 65, 'skEnc': 32, 'uid': 16, 'overhead': 20}
reg_mlkem = {'pkSig': 65, 'skEnc': 32, 'uid': 16, 'overhead': 20}

# 同类方案总通信开销对比 (bytes, 完整认证流程)
scheme_overhead = {
    'Our Scheme\n(ECDH)':   {'auth': 358, 'reg': 133},
    'Our Scheme\n(ML-KEM)': {'auth': 2620, 'reg': 133},
    'Li et al.\n2020':      {'auth': 512, 'reg': 256},
    'Das et al.\n2019':     {'auth': 640, 'reg': 320},
    'Wazid et al.\n2019':   {'auth': 480, 'reg': 240},
    'TLS 1.3\n(reference)': {'auth': 4096, 'reg': 0},
}

# ==========================================
# 图1: 各步骤消息大小堆积柱状图
# ==========================================
fig, axes = plt.subplots(2, 2, figsize=(15, 11))

ax1 = axes[0, 0]

# ECDH步骤分解
steps = ['Step1\nAuth Req', 'Step2\nChallenge', 'Step3\nResponse', 'Step4\nConfirm']
ecdh_totals = [16, 161, 197, 104]
mlkem_totals = [16, 1280, 1220, 104]

# 详细分解颜色
colors_detail = ['#42A5F5', '#66BB6A', '#FFA726', '#EF5350', '#AB47BC', '#78909C']

# ECDH堆积
ecdh_breakdown = [
    [16, 0, 0, 0],           # uid
    [0, 65, 0, 0],           # dhpubS/pkKEM
    [0, 72, 0, 0],           # serversigm
    [0, 24, 0, 0],           # ts+nonce
    [0, 0, 165, 0],          # tau
    [0, 0, 32, 0],           # tagU
    [0, 0, 0, 104],          # tagS+sig
]
labels_d = ['UID', 'DH/KEM PubKey', 'Server Sig', 'TS+Nonce', 'τ (ciphertext)', 'tagU', 'tagS+Sig']

x = np.arange(len(steps))
w = 0.35
bottoms_e = np.zeros(4)
bottoms_m = np.zeros(4)

mlkem_breakdown = [
    [16, 0, 0, 0],
    [0, 1184, 0, 0],
    [0, 72, 0, 0],
    [0, 24, 0, 0],
    [0, 0, 1188, 0],
    [0, 0, 32, 0],
    [0, 0, 0, 104],
]

for i, (layer_e, layer_m, label, color) in enumerate(zip(ecdh_breakdown, mlkem_breakdown, labels_d, colors_detail)):
    le = np.array(layer_e)
    lm = np.array(mlkem_breakdown[i])
    ax1.bar(x - w/2, le, w, bottom=bottoms_e, color=color, edgecolor='white', lw=0.5,
            label=label if i == 0 or any(v > 0 for v in le) else '_')
    ax1.bar(x + w/2, lm, w, bottom=bottoms_m, color=color, edgecolor='white', lw=0.5)
    bottoms_e += le
    bottoms_m += lm

for i, (te, tm) in enumerate(zip(ecdh_totals, mlkem_totals)):
    ax1.text(i - w/2, te + 20, f'{te}B', ha='center', fontsize=8, fontweight='bold', color='#1976D2')
    ax1.text(i + w/2, tm + 20, f'{tm}B', ha='center', fontsize=8, fontweight='bold', color='#7B1FA2')

ax1.set_xticks(x)
ax1.set_xticklabels(steps, fontsize=9)
ax1.set_ylabel('Message Size (bytes)', fontsize=11)
ax1.set_title('Per-Step Message Size\n(Blue=ECDH, Purple=ML-KEM)', fontsize=11, fontweight='bold')
ax1.legend(fontsize=8, loc='upper right')
ax1.grid(True, axis='y', alpha=0.3)
ax1.set_ylim(0, 1600)

# ==========================================
# 图2: 总通信开销对比
# ==========================================
ax2 = axes[0, 1]
scheme_names = list(scheme_overhead.keys())
auth_vals = [scheme_overhead[s]['auth'] for s in scheme_names]
reg_vals = [scheme_overhead[s]['reg'] for s in scheme_names]
scheme_colors = ['#1976D2', '#7B1FA2', '#FF9800', '#F44336', '#9E9E9E', '#4CAF50']

x2 = np.arange(len(scheme_names))
w2 = 0.35
b1 = ax2.bar(x2 - w2/2, auth_vals, w2, label='Auth Phase', color=scheme_colors, alpha=0.85,
             edgecolor='black', lw=0.5)
b2 = ax2.bar(x2 + w2/2, reg_vals, w2, label='Registration Phase', color=scheme_colors, alpha=0.4,
             edgecolor='black', lw=0.5, hatch='//')

for bar, val in zip(b1, auth_vals):
    ax2.text(bar.get_x() + bar.get_width()/2, val + 30,
             f'{val}B', ha='center', va='bottom', fontsize=8, fontweight='bold')

ax2.set_xticks(x2)
ax2.set_xticklabels(scheme_names, fontsize=9)
ax2.set_ylabel('Total Communication Overhead (bytes)', fontsize=11)
ax2.set_title('Communication Overhead Comparison', fontsize=11, fontweight='bold')
ax2.legend(fontsize=10)
ax2.grid(True, axis='y', alpha=0.3)
ax2.set_ylim(0, 5200)

# ==========================================
# 图3: ECDH vs ML-KEM 数据大小对比
# ==========================================
ax3 = axes[1, 0]
params = ['Public Key', 'Ciphertext/\nDH PubKey', 'Shared\nSecret', 'Total Auth\nOverhead']
ecdh_sizes =  [65,   65,   32,  358]
mlkem_sizes = [1184, 1088, 32, 2620]

x3 = np.arange(len(params))
w3 = 0.35
b3 = ax3.bar(x3 - w3/2, ecdh_sizes, w3, label='ECDH P-256', color='#1976D2', alpha=0.85,
             edgecolor='black', lw=0.5)
b4 = ax3.bar(x3 + w3/2, mlkem_sizes, w3, label='ML-KEM-768', color='#7B1FA2', alpha=0.85,
             edgecolor='black', lw=0.5)

for bar, val in zip(b3, ecdh_sizes):
    ax3.text(bar.get_x() + bar.get_width()/2, val + 15,
             f'{val}B', ha='center', va='bottom', fontsize=9)
for bar, val in zip(b4, mlkem_sizes):
    ax3.text(bar.get_x() + bar.get_width()/2, val + 15,
             f'{val}B', ha='center', va='bottom', fontsize=9)

# 标注倍数
for i, (e, m) in enumerate(zip(ecdh_sizes, mlkem_sizes)):
    if e > 0:
        ratio = m / e
        ax3.text(i, max(e, m) + 80, f'{ratio:.1f}×', ha='center', fontsize=10,
                 color='red', fontweight='bold')

ax3.set_xticks(x3)
ax3.set_xticklabels(params, fontsize=10)
ax3.set_ylabel('Size (bytes)', fontsize=11)
ax3.set_title('ECDH vs ML-KEM-768 Data Size\n(PQC overhead analysis)', fontsize=11, fontweight='bold')
ax3.legend(fontsize=10)
ax3.grid(True, axis='y', alpha=0.3)
ax3.set_ylim(0, 3200)

# ==========================================
# 图4: 通信开销 vs 安全级别散点图
# ==========================================
ax4 = axes[1, 1]
security_levels = [128, 192, 128, 128, 128, 128]
overhead_vals = [358, 2620, 512, 640, 480, 4096]
scheme_labels = ['Our\n(ECDH)', 'Our\n(ML-KEM)', 'Li\n2020', 'Das\n2019', 'Wazid\n2019', 'TLS 1.3']
point_colors = ['#1976D2', '#7B1FA2', '#FF9800', '#F44336', '#9E9E9E', '#4CAF50']
point_sizes = [200, 200, 150, 150, 150, 150]

for x_val, y_val, label, color, size in zip(security_levels, overhead_vals, scheme_labels, point_colors, point_sizes):
    ax4.scatter(x_val, y_val, c=color, s=size, zorder=5, edgecolors='black', lw=0.8)
    ax4.annotate(label, (x_val, y_val), textcoords='offset points',
                 xytext=(8, 5), fontsize=9, color=color, fontweight='bold')

ax4.set_xlabel('Security Level (bits)', fontsize=11)
ax4.set_ylabel('Total Auth Communication (bytes)', fontsize=11)
ax4.set_title('Security Level vs. Communication Overhead\n(Lower-right = better)', fontsize=11, fontweight='bold')
ax4.grid(True, alpha=0.3)
ax4.set_xlim(100, 220)
ax4.set_ylim(0, 5000)

# 标注最优区域
ax4.annotate('Optimal\nZone', xy=(192, 2620), xytext=(160, 800),
             arrowprops=dict(arrowstyle='->', color='green', lw=1.5),
             fontsize=10, color='green', fontweight='bold')

plt.suptitle('Communication Overhead Analysis\n(Per authentication session)',
             fontsize=13, fontweight='bold')
plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch6/fig6_communication_overhead.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch6/fig6_communication_overhead.png',
            dpi=300, bbox_inches='tight')
print("P3 done: fig6_communication_overhead.pdf/png")
