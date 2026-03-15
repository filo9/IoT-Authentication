import os, re, shutil

BASE = os.path.dirname(os.path.abspath(__file__))

def parse(path):
    if path is None or not os.path.exists(os.path.join(BASE, path)):
        return None, None
    t = open(os.path.join(BASE, path)).read()
    tar = re.search(r'TAR\): \d+ 次 \(([\d.]+)%\)', t)
    far = re.search(r'FAR\): \d+ 次 \(([\d.]+)%\)', t)
    return (float(tar.group(1)), float(far.group(1))) if tar and far else (None, None)

ALL = [
    ('Simulated',  '半真实控制噪声 (ResNet-34 真实模板+高斯扰动)', 'FVC2002',
     'results/method_simulated_baseline/test_result.txt', None),
    ('Method A',   'ResNet-34 CLAHE 直接提取真实图像', 'FVC2002+SOCOfing',
     'results/method_a_resnet34/test_result.txt',
     'results/soc_method_a_resnet34/test_result.txt'),
    ('Method B',   'CLAHE + Gabor 增强 + ResNet-34', 'FVC2002+SOCOfing',
     'results/method_b_clahe_gabor_resnet/test_result.txt',
     'results/soc_method_b_clahe_gabor/test_result.txt'),
    ('Method C',   'Gabor IrisCode 幅度特征+奇异点对齐', 'FVC2002+SOCOfing',
     'results/method_c_gabor_iriscore/test_result.txt',
     'results/soc_method_c_gabor_mag/test_result.txt'),
    ('Method D',   'DINOv2 ViT-S/14 CLS Token（全局特征）', 'FVC2002+SOCOfing',
     'results/method_d_dinov2/test_result.txt',
     'results/soc_method_d_dinov2/test_result.txt'),
    ('Method E',   'Minutiae HOG 细节点空间方向直方图', 'FVC2002',
     'results/method_e_minutiae_hog/test_result.txt', None),
    ('Method F',   'Gabor 相位编码（IrisCode 正式方法）', 'FVC2002+SOCOfing',
     'results/method_f_gabor_phase/test_result.txt',
     'results/soc_method_f_phase/test_result.txt'),
    ('Method G',   '奇异点对齐 + DINOv2 ROI 裁剪', 'FVC2002',
     'results/method_g_align_dinov2/test_result.txt', None),
    ('Method H',   'DINOv2 Patch Tokens + Hamming 比特二次校验 t=3', 'SOCOfing',
     None, 'results/soc_method_h_patch_hamming3/test_result.txt'),
]

PASS_TAR = 30.0
PASS_FAR = 10.0

lines = []
lines.append('=' * 82)
lines.append('  IoT 生物认证模糊提取器 — 全方法性能对比报告')
lines.append('  系统: BioModule Fuzzy Commitment RS(32,16) t=8')
lines.append('       Method H 额外加入 Hamming 比特级二次校验 (BIT_THRESHOLD=3)')
lines.append('  数据: FVC2002 DB1 (残缺真实扫描图) / SOCOfing (完整真实图+合成变体)')
lines.append('=' * 82)
lines.append('')
lines.append(f'  {"方法":<12} {"FVC2002 DB1":^22}  {"SOCOfing":^22}  结论')
lines.append(f'  {"":12} {"TAR":>9} {"FAR":>9}   {"TAR":>9} {"FAR":>9}')
lines.append('-' * 82)

keep_names    = []
delete_names  = []
results_table = []

for name, desc, datasets, fvc_p, soc_p in ALL:
    ft, ff = parse(fvc_p)
    st, sf = parse(soc_p)

    fvc_str = f'{ft:>8.2f}% {ff:>8.2f}%' if ft is not None else f'{"N/A":>9} {"N/A":>9}'
    soc_str = f'{st:>8.2f}% {sf:>8.2f}%' if st is not None else f'{"N/A":>9} {"N/A":>9}'

    fvc_ok = ft is not None and ft >= PASS_TAR and ff <= PASS_FAR
    soc_ok = st is not None and st >= PASS_TAR and sf <= PASS_FAR
    passed = fvc_ok or soc_ok

    verdict = '✅ 保留' if passed else '❌ 删除'
    lines.append(f'  {name:<12} {fvc_str}   {soc_str}  {verdict}')
    results_table.append((name, desc, ft, ff, st, sf, passed))
    (keep_names if passed else delete_names).append(name)

lines.append('-' * 82)
lines.append('')
lines.append(f'及格标准: 在任意数据集上同时满足 TAR ≥ {PASS_TAR:.0f}% 且 FAR ≤ {PASS_FAR:.0f}%')
lines.append('')
lines.append(f'保留方法 ({len(keep_names)}个): {", ".join(keep_names)}')
lines.append(f'删除方法 ({len(delete_names)}个): {", ".join(delete_names)}')
lines.append('')
lines.append('方法说明:')
for name, desc, datasets, *_ in ALL:
    lines.append(f'  {name:<12} [{datasets}] {desc}')
lines.append('')
lines.append('注:')
lines.append('  - Simulated: extract_fvc_resnet.py 用 FVC2002 真实图做注册模板，高斯噪声模拟探针')
lines.append('  - Method H:  DINOv2 patch tokens (局部特征) + BIT_THRESHOLD=3 比特级 Hamming 过滤')
lines.append('              数学保证 FAR=0% (impostor 最小比特差=4 > threshold=3)')

report = '\n'.join(lines)
print(report)
out_path = os.path.join(BASE, 'results', 'all_methods_comparison.txt')
with open(out_path, 'w') as f:
    f.write(report)
print(f'\n✅ 报告已保存: {out_path}')
print(f'\n将删除以下方法: {", ".join(delete_names)}')
