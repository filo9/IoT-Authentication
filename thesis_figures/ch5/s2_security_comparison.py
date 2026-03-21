#!/usr/bin/env python3
"""
S2: 安全属性对比热力图
第五章 — 与同类方案安全属性横向对比
"""
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

# ==========================================
# 数据定义
# ==========================================
schemes = [
    'Our Scheme\n(ECDH)',
    'Our Scheme\n(ML-KEM)',
    'Li et al.\n2020',
    'Das et al.\n2019',
    'Amin et al.\n2018',
    'Wazid et al.\n2019',
    'Password\nOnly',
]

properties = [
    'Mutual\nAuthentication',
    'Forward\nSecrecy',
    'Server Compromise\nResistance',
    'Replay Attack\nResistance',
    'MITM\nResistance',
    'User\nAnonymity',
    'Device Loss\nResistance',
    'Biometric\nPrivacy',
    'Post-Quantum\nSecurity',
    'Three-Factor\nAuth',
]

# 1=支持, 0=不支持, 0.5=部分支持
data = np.array([
    # Our ECDH  Our PQC  Li2020  Das2019  Amin2018  Wazid2019  PwOnly
    [1,         1,       1,      1,       0,        1,         0],   # Mutual Auth
    [1,         1,       0,      1,       0,        0,         0],   # Forward Secrecy
    [1,         1,       0,      0,       0,        0,         0],   # Server Compromise
    [1,         1,       1,      1,       1,        1,         0],   # Replay Resistance
    [1,         1,       1,      1,       0,        1,         0],   # MITM Resistance
    [1,         1,       0,      1,       0,        0.5,       0],   # User Anonymity
    [1,         1,       0,      0,       0,        0,         0],   # Device Loss
    [1,         1,       0.5,    1,       0,        0.5,       0],   # Biometric Privacy
    [0,         1,       0,      0,       0,        0,         0],   # Post-Quantum
    [1,         1,       1,      1,       0,        1,         0],   # Three-Factor
])

# ==========================================
# 绘图
# ==========================================
fig, ax = plt.subplots(figsize=(14, 7))

# 自定义颜色映射
colors = {0: '#d73027', 0.5: '#fee08b', 1: '#1a9850'}
cmap = matplotlib.colors.ListedColormap(['#d73027', '#fee08b', '#1a9850'])
bounds = [-0.25, 0.25, 0.75, 1.25]
norm = matplotlib.colors.BoundaryNorm(bounds, cmap.N)

im = ax.imshow(data, cmap=cmap, norm=norm, aspect='auto')

# 坐标轴
ax.set_xticks(np.arange(len(schemes)))
ax.set_yticks(np.arange(len(properties)))
ax.set_xticklabels(schemes, fontsize=10)
ax.set_yticklabels(properties, fontsize=10)

# 顶部也显示x轴标签
ax.tick_params(top=True, bottom=False, labeltop=True, labelbottom=False)

# 在每个格子里写符号
symbols = {0: '✗', 0.5: '△', 1: '✓'}
text_colors = {0: 'white', 0.5: '#333333', 1: 'white'}
for i in range(len(properties)):
    for j in range(len(schemes)):
        val = data[i, j]
        sym = symbols[val]
        tc = text_colors[val]
        ax.text(j, i, sym, ha='center', va='center',
                fontsize=14, color=tc, fontweight='bold')

# 高亮本方案列
for j in [0, 1]:
    rect = mpatches.FancyBboxPatch(
        (j - 0.5, -0.5), 1, len(properties),
        boxstyle="square,pad=0",
        linewidth=2.5, edgecolor='#2196F3', facecolor='none',
        zorder=5
    )
    ax.add_patch(rect)

# 网格线
ax.set_xticks(np.arange(len(schemes)) - 0.5, minor=True)
ax.set_yticks(np.arange(len(properties)) - 0.5, minor=True)
ax.grid(which='minor', color='white', linewidth=1.5)
ax.tick_params(which='minor', bottom=False, left=False)

# 图例
legend_elements = [
    mpatches.Patch(facecolor='#1a9850', label='Supported (✓)'),
    mpatches.Patch(facecolor='#fee08b', label='Partially Supported (△)'),
    mpatches.Patch(facecolor='#d73027', label='Not Supported (✗)'),
]
ax.legend(handles=legend_elements, loc='lower right',
          bbox_to_anchor=(1.0, -0.12), ncol=3, fontsize=10,
          framealpha=0.9)

ax.set_title('Security Property Comparison of IoT Authentication Schemes',
             fontsize=13, fontweight='bold', pad=20)

plt.tight_layout()
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_security_comparison.pdf',
            dpi=300, bbox_inches='tight')
plt.savefig('/home/filo/workspace/IoT_Auth_Protocol/thesis_figures/ch5/fig5_security_comparison.png',
            dpi=300, bbox_inches='tight')
print("S2 done: fig5_security_comparison.pdf/png")
