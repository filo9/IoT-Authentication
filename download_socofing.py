"""
SOCOfing 数据集下载 + 测试一键脚本
================================================================
SOCOfing (Sokoto Coventry Fingerprint Dataset):
  - 600 名非洲受试者 × 10 根手指 × 1 张真实图 = 6000 张高质量指纹图
  - 三级合成变体：Easy / Medium / Hard（模拟真实使用场景）
  - 图像分辨率高，手指覆盖完整，无 FVC2002 的残缺问题
  - 完全免费，仅需 Kaggle 免费账号

获取 Kaggle API Key：
  1. 浏览器访问 https://www.kaggle.com/settings/account
  2. 滚动到 "API" → "Create New API Token"
  3. 下载 kaggle.json，放到 ~/.kaggle/kaggle.json
  4. chmod 600 ~/.kaggle/kaggle.json

使用：
  python3 download_socofing.py            # 下载 + 自动测试
  python3 download_socofing.py --skip_download  # 已下载则跳过
"""
import os, sys, subprocess, csv, shutil, warnings, argparse, re
import cv2, numpy as np, torch, torchvision.transforms as transforms
import torch.nn.functional as F
from PIL import Image

warnings.filterwarnings("ignore")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "socofing")


def download_socofing():
    """用 kaggle CLI 下载数据集。"""
    key_path = os.path.expanduser("~/.kaggle/kaggle.json")
    if not os.path.exists(key_path):
        print("❌ 未找到 ~/.kaggle/kaggle.json")
        print()
        print("请按以下步骤获取 API Key：")
        print("  1. 访问 https://www.kaggle.com/settings/account")
        print("  2. 点击 'Create New API Token' 下载 kaggle.json")
        print("  3. cp ~/Downloads/kaggle.json ~/.kaggle/kaggle.json")
        print("  4. chmod 600 ~/.kaggle/kaggle.json")
        print("  5. 重新运行本脚本")
        sys.exit(1)

    os.makedirs(DATA_DIR, exist_ok=True)
    print("⬇️  下载 SOCOfing 数据集 (~400MB)...")
    result = subprocess.run(
        ["kaggle", "datasets", "download", "ruizgara/socofing",
         "-p", DATA_DIR, "--unzip"],
        capture_output=False
    )
    if result.returncode != 0:
        print("❌ 下载失败，请检查 kaggle.json 是否正确")
        sys.exit(1)
    print("✅ 下载完毕")


def load_socofing_dataset(data_dir, max_subjects=100, finger="Left_index_finger"):
    """
    加载 SOCOfing 数据集。
    返回 dataset：{subject_id: [(tag, path), ...]}
    tag: 'real' / 'easy' / 'medium'
    """
    real_dir   = os.path.join(data_dir, "Real")
    easy_dir   = os.path.join(data_dir, "Altered", "Altered-Easy")
    medium_dir = os.path.join(data_dir, "Altered", "Altered-Medium")

    if not os.path.exists(real_dir):
        # 也可能直接放在 data_dir 下
        real_dir   = os.path.join(data_dir, "SOCOFing", "Real")
        easy_dir   = os.path.join(data_dir, "SOCOFing", "Altered", "Altered-Easy")
        medium_dir = os.path.join(data_dir, "SOCOFing", "Altered", "Altered-Medium")

    if not os.path.exists(real_dir):
        raise FileNotFoundError(f"找不到 SOCOfing Real 目录，请确认下载并解压到 {data_dir}")

    dataset = {}
    for fname in sorted(os.listdir(real_dir)):
        if not fname.lower().endswith(".bmp"):
            continue
        if finger not in fname:
            continue
        # 文件名: 1__M_Left_index_finger.BMP
        sid = fname.split("__")[0]
        real_path = os.path.join(real_dir, fname)

        # 找 Easy 变体（可能有多种后缀）
        easy_path = None
        for suffix in ["_Obl.BMP", "_CR.BMP", "_Zcut.BMP"]:
            candidate = os.path.join(easy_dir, fname.replace(".BMP", suffix))
            if os.path.exists(candidate):
                easy_path = candidate
                break
        # 直接在 easy_dir 找同名文件
        if easy_path is None:
            direct = os.path.join(easy_dir, fname)
            if os.path.exists(direct):
                easy_path = direct

        medium_path = None
        for suffix in ["_Obl.BMP", "_CR.BMP", "_Zcut.BMP"]:
            candidate = os.path.join(medium_dir, fname.replace(".BMP", suffix))
            if os.path.exists(candidate):
                medium_path = candidate
                break

        entries = [("real", real_path)]
        if easy_path:
            entries.append(("easy", easy_path))
        if medium_path:
            entries.append(("medium", medium_path))

        if len(entries) >= 2:  # 至少 real + 1 个变体
            dataset[sid] = entries

    subjects = sorted(dataset.keys(), key=lambda x: int(x))[:max_subjects]
    print(f"  找到 {len(subjects)} 个有效受试者（各含 Real + 变体）")
    if subjects:
        print(f"  示例: 受试者 {subjects[0]} 有 {len(dataset[subjects[0]])} 个样本")
        for tag, path in dataset[subjects[0]]:
            print(f"    [{tag}] {os.path.basename(path)}")
    return {s: dataset[s] for s in subjects}


def extract_dinov2_feat(model, proj, transform, img_path):
    img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    img   = clahe.apply(img)
    pil   = Image.fromarray(img)
    t     = transform(pil).unsqueeze(0)
    with torch.no_grad():
        feat = model(t)
        feat = F.normalize(feat, p=2, dim=1).squeeze().numpy()
    feat = feat @ proj
    feat = feat - feat.mean()
    return feat.astype(np.float32)


def run_test(dataset, model, proj, transform, result_tag):
    """提取特征 → 生成 CSV → 运行 C++ 测试 → 保存结果。"""
    feat_dir   = os.path.join(BASE_DIR, "fingerprint_features")
    result_dir = os.path.join(BASE_DIR, "results", result_tag)
    os.makedirs(feat_dir, exist_ok=True)
    os.makedirs(result_dir, exist_ok=True)

    # 提取特征
    users   = sorted(dataset.keys(), key=lambda x: int(x))
    key_map = {}  # (uid, sample_idx) → key_name
    print(f"  提取特征（{len(users)} 个用户）...")
    for u in users:
        for idx, (tag, path) in enumerate(dataset[u]):
            key = f"{u}_{idx+1}"
            key_map[(u, idx+1)] = key
            out  = os.path.join(feat_dir, f"{key}_vault.dat")
            feat = extract_dinov2_feat(model, proj, transform, path)
            if feat is not None:
                feat.tofile(out)

    # 生成 CSV
    rows = []
    for u in users:
        n = len(dataset[u])
        for i in range(1, n+1):
            for j in range(i+1, n+1):
                rows.append(["Genuine", f"{u}_{i}_vault", f"{u}_{j}_vault", 0])
    for u1 in users:
        for u2 in users:
            if u1 == u2: continue
            # 用 real (index 1) 做 impostor 对
            rows.append(["Impostor", f"{u1}_1_vault", f"{u2}_1_vault", 0])

    csv_path = os.path.join(BASE_DIR, "unified_test_plan_vault.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["Type","Template","Probe","ErrorBits"]); w.writerows(rows)

    gen_n = sum(1 for r in rows if r[0] == "Genuine")
    imp_n = sum(1 for r in rows if r[0] == "Impostor")
    print(f"  测试规模: Genuine={gen_n}, Impostor={imp_n}")

    result = subprocess.run(["./test_batch_vault"], cwd=os.path.join(BASE_DIR, "build"),
                            capture_output=True, text=True)
    print(result.stdout)

    with open(os.path.join(result_dir, "test_result.txt"), "w") as f:
        f.write(result.stdout)
    shutil.copy(csv_path, os.path.join(result_dir, "unified_test_plan_vault.csv"))
    feat_save = os.path.join(result_dir, "fingerprint_features")
    if os.path.exists(feat_save): shutil.rmtree(feat_save)
    shutil.copytree(feat_dir, feat_save)
    print(f"  结果已保存 → {result_dir}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip_download", action="store_true")
    parser.add_argument("--data_dir", default=DATA_DIR)
    parser.add_argument("--max_subjects", type=int, default=100,
                        help="使用的受试者数量（默认 100）")
    parser.add_argument("--finger", default="Left_index_finger",
                        help="使用哪根手指（默认左食指）")
    args = parser.parse_args()

    if not args.skip_download:
        download_socofing()

    print("\n[SOCOfing] 加载数据集...")
    dataset = load_socofing_dataset(args.data_dir, args.max_subjects, args.finger)

    print("\n[模型] 加载 DINOv2 ViT-S/14...")
    model = torch.hub.load("facebookresearch/dinov2", "dinov2_vits14", verbose=False)
    model.eval()
    np.random.seed(42)
    proj = np.random.randn(model.embed_dim, 512).astype(np.float32)
    proj /= np.linalg.norm(proj, axis=0, keepdims=True)
    transform = transforms.Compose([
        transforms.Resize((224, 224)), transforms.Grayscale(3), transforms.ToTensor(),
        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
    ])

    print(f"\n[测试] SOCOfing DINOv2（{args.max_subjects} 受试者，左食指）")
    run_test(dataset, model, proj, transform, "socofing_dinov2")

    # 恢复原始指纹数据
    print("\n[恢复] 还原 FVC2002 模拟方案默认数据...")
    subprocess.run(["python3", "-W", "ignore", "extract_fvc_resnet.py"],
                   cwd=BASE_DIR, capture_output=True)
    print("✅ 完成！查看 results/socofing_dinov2/ 目录")


if __name__ == "__main__":
    main()
