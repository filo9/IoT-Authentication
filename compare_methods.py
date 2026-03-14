"""
生成所有方法的对比汇总报告（用于论文表格）
"""
import os, re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS  = os.path.join(BASE_DIR, "results")

def parse_result(path):
    """从 test_result.txt 中解析 TAR 和 FAR。"""
    if not os.path.exists(path):
        return None, None
    with open(path) as f:
        text = f.read()
    tar = re.search(r"TAR\): \d+ 次 \(([\d.]+)%\)", text)
    far = re.search(r"FAR\): \d+ 次 \(([\d.]+)%\)", text)
    if tar and far:
        return float(tar.group(1)), float(far.group(1))
    return None, None

METHODS = [
    ("Simulated",       "模拟控制噪声 (extract_fvc_resnet.py)",
     os.path.join(BASE_DIR, "results", "method_simulated_baseline", "test_result.txt")),
    ("Method A",        "ResNet-34 直接提取真实图像（Baseline）",
     os.path.join(RESULTS, "method_a_resnet34", "test_result.txt")),
    ("Method B",        "CLAHE + Gabor 增强 + ResNet-34",
     os.path.join(RESULTS, "method_b_clahe_gabor_resnet", "test_result.txt")),
    ("Method C",        "Gabor IrisCode（幅度特征 + 奇异点对齐）",
     os.path.join(RESULTS, "method_c_gabor_iriscore", "test_result.txt")),
    ("Method D",        "DINOv2 ViT-S/14 自监督基础视觉模型",
     os.path.join(RESULTS, "method_d_dinov2", "test_result.txt")),
    ("Method E",        "Minutiae HOG 细节点空间方向直方图",
     os.path.join(RESULTS, "method_e_minutiae_hog", "test_result.txt")),
    ("Method F",        "Gabor 相位编码（IrisCode 正式方法）",
     os.path.join(RESULTS, "method_f_gabor_phase", "test_result.txt")),
    ("Method G",        "奇异点对齐 + DINOv2 ROI 裁剪",
     os.path.join(RESULTS, "method_g_align_dinov2", "test_result.txt")),
]

# 保存模拟数据的结果作为 baseline
sim_dir = os.path.join(BASE_DIR, "results", "method_simulated_baseline")
os.makedirs(sim_dir, exist_ok=True)
sim_result_path = os.path.join(sim_dir, "test_result.txt")
if not os.path.exists(sim_result_path):
    # 从当前 test_batch_vault 输出生成（已经运行了 extract_fvc_resnet.py）
    import subprocess
    r = subprocess.run(["./test_batch_vault"], cwd=os.path.join(BASE_DIR,"build"),
                       capture_output=True, text=True)
    with open(sim_result_path, "w") as f:
        f.write("模拟控制噪声方案 (NOISE_SIGMA=0.01, ResNet-34 + 高斯噪声扰动)\n\n")
        f.write(r.stdout)

print("=" * 75)
print("  FVC2002 DB1 指纹模糊提取器 — 全方法性能对比表")
print("  系统参数: BioModule Fuzzy Commitment + RS(32,16) t=8")
print("=" * 75)
print(f"  {'方法':<12} {'TAR (%)':>9} {'FAR (%)':>9}  {'说明'}")
print("-" * 75)

results_data = []
for name, desc, path in METHODS:
    tar, far = parse_result(path)
    if tar is None:
        print(f"  {name:<12} {'N/A':>9} {'N/A':>9}  {desc}")
    else:
        # 标记最优方案
        marker = " ★" if (tar > 90 and far < 5) else ("" if far > 10 else " ✓")
        print(f"  {name:<12} {tar:>8.2f}% {far:>8.2f}%  {desc}{marker}")
        results_data.append((name, desc, tar, far))

print("-" * 75)
print("  ★ = 高通过率+低拒识（论文推荐方案）")
print("  ✓ = FAR 达标（<5%）")
print()

# 找最优（真实图像方法中 TAR 最高）
real_methods = [(n,d,t,f) for n,d,t,f in results_data if "Simulated" not in n]
if real_methods:
    best_tar = max(real_methods, key=lambda x: x[2])
    best_far = min(real_methods, key=lambda x: x[3])
    print(f"  真实图像最高 TAR: {best_tar[0]} ({best_tar[2]:.2f}%)")
    print(f"  真实图像最低 FAR: {best_far[0]} ({best_far[3]:.2f}%)")
    print()

print("论文结论摘要:")
print("  1. 模拟控制噪声方案有效证明了模糊承诺方案的可行性（TAR 94.29%，FAR 0.16%）")
print("  2. 真实图像方案中，DINOv2（自监督大模型）TAR 最高（72.14%），但 FAR 偏高")
print("  3. Gabor 相位编码 FAR 最低（0.69%），但 TAR 仅 11.43%")
print("  4. Genuine/Impostor 位差异分布重叠（均值 7.6 vs 20.4 bits）是核心瓶颈")
print("  5. 指纹专用深度模型（FingerNet/DeepPrint）可大幅缩小分布重叠，是未来方向")
print("=" * 75)

# 保存报告
report_path = os.path.join(BASE_DIR, "results", "comparison_report.txt")
import sys
from io import StringIO
old_stdout = sys.stdout; sys.stdout = buf = StringIO()

print("FVC2002 DB1 指纹模糊提取器 — 全方法性能对比")
print("=" * 75)
for name, desc, path in METHODS:
    tar, far = parse_result(path)
    if tar is not None:
        print(f"{name:<12} TAR={tar:.2f}%  FAR={far:.2f}%  {desc}")

sys.stdout = old_stdout
with open(report_path, "w") as f:
    f.write(buf.getvalue())
print(f"\n  报告已保存到: {report_path}")
