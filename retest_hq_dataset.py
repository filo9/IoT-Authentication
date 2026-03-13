"""
FVC2002 DB1 高质量子集重测 + SOCOfing 数据集支持
================================================================
用法：
  1. 高质量 FVC2002 子集（立即可用）:
     python3 retest_hq_dataset.py --dataset fvc2002_hq

  2. SOCOfing（下载后可用）:
     python3 retest_hq_dataset.py --dataset socofing --data_dir ./socofing

SOCOfing 下载步骤:
  1. 注册 https://www.kaggle.com 免费账号
  2. 头像 → Settings → API → Create New Token → 下载 kaggle.json
  3. cp kaggle.json ~/.kaggle/kaggle.json && chmod 600 ~/.kaggle/kaggle.json
  4. kaggle datasets download ruizgara/socofing -p ./socofing --unzip
"""
import os, csv, shutil, subprocess, sys, warnings, argparse
import cv2, numpy as np, torch, torchvision.transforms as transforms
import torch.nn.functional as F
from PIL import Image

warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ── 数据集加载器 ──────────────────────────────────────────────────────────────
def load_fvc2002_hq(img_dir, coverage_thresh=0.80, min_samples=4):
    """加载 FVC2002 DB1 高质量子集（过滤残缺图像）。"""
    users = [str(i) for i in range(101, 111)]
    dataset = {}  # {user_id: [(sample_idx, img_path), ...]}
    for u in users:
        samples = []
        for i in range(1, 9):
            p = os.path.join(img_dir, f"{u}_{i}.tif")
            if not os.path.exists(p):
                continue
            img = cv2.imread(p, cv2.IMREAD_GRAYSCALE)
            _, thresh = cv2.threshold(img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            cov = thresh.mean() / 255
            if cov >= coverage_thresh:
                samples.append((i, p))
        if len(samples) >= min_samples:
            dataset[u] = samples
    return dataset


def load_socofing(data_dir, max_users=60):
    """
    加载 SOCOfing 数据集。
    结构: data_dir/Real/*.BMP, data_dir/Altered/Altered-Easy/*.BMP
    文件名格式: {ID}__M_Left_index_finger.BMP (Real)
               {ID}__M_Left_index_finger_Obl.BMP (Altered-Easy)
    将 Real 作为模板，Altered-Easy 作为探针。
    """
    real_dir = os.path.join(data_dir, "Real")
    easy_dir = os.path.join(data_dir, "Altered", "Altered-Easy")
    if not os.path.exists(real_dir):
        raise FileNotFoundError(f"找不到 {real_dir}，请先下载 SOCOfing 数据集")

    dataset = {}
    for f in sorted(os.listdir(real_dir)):
        if not f.lower().endswith(".bmp"):
            continue
        # 文件名: 1__M_Left_index_finger.BMP
        uid = f.split("__")[0]
        # 只取左食指（避免同一人同指不同手混淆）
        if "Left_index_finger" not in f:
            continue
        real_path = os.path.join(real_dir, f)
        # 对应的 Easy 变体
        easy_name = f.replace(".BMP", "_Obl.BMP")
        easy_path = os.path.join(easy_dir, easy_name)
        if os.path.exists(easy_path):
            if uid not in dataset:
                dataset[uid] = []
            dataset[uid].append(("real", real_path))
            dataset[uid].append(("easy", easy_path))

    # 限制用户数
    all_users = sorted(dataset.keys(), key=lambda x: int(x))[:max_users]
    return {u: dataset[u] for u in all_users if len(dataset[u]) >= 2}


# ── 特征提取（所有方法）──────────────────────────────────────────────────────
def extract_dinov2(model, proj_matrix, transform, img_path):
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
    feat = feat @ proj_matrix
    feat = feat - feat.mean()
    return feat.astype(np.float32)


def extract_resnet34(model, transform, img_path):
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
    feat = feat - feat.mean()
    return feat.astype(np.float32)


# ── 主程序 ──────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["fvc2002_hq", "socofing"], default="fvc2002_hq")
    parser.add_argument("--data_dir", default="./fvc2002_db1")
    parser.add_argument("--method",   choices=["dinov2", "resnet34", "all"], default="all")
    parser.add_argument("--coverage", type=float, default=0.80,
                        help="FVC2002 最低覆盖率阈值（默认 0.80）")
    args = parser.parse_args()

    # 加载数据集
    if args.dataset == "fvc2002_hq":
        print(f"[数据集] FVC2002 DB1 高质量子集（覆盖率 ≥ {args.coverage:.0%}）")
        dataset = load_fvc2002_hq(args.data_dir, args.coverage)
    else:
        print("[数据集] SOCOfing (Real + Altered-Easy)")
        dataset = load_socofing(args.data_dir)

    print(f"  合格用户: {len(dataset)} 个")
    for u, samples in list(dataset.items())[:3]:
        print(f"  用户 {u}: {len(samples)} 个样本")
    if len(dataset) > 3:
        print(f"  ...")

    # 方法列表
    methods_to_run = ["dinov2", "resnet34"] if args.method == "all" else [args.method]

    # ── 模型加载 ───────────────────────────────────────────────────────────
    models = {}

    if "dinov2" in methods_to_run:
        print("\n[模型] 加载 DINOv2 ViT-S/14...")
        m = torch.hub.load("facebookresearch/dinov2", "dinov2_vits14", verbose=False)
        m.eval()
        np.random.seed(42)
        proj = np.random.randn(m.embed_dim, 512).astype(np.float32)
        proj /= np.linalg.norm(proj, axis=0, keepdims=True)
        tf_dino = transforms.Compose([
            transforms.Resize((224, 224)), transforms.Grayscale(3), transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])
        models["dinov2"] = (m, proj, tf_dino)

    if "resnet34" in methods_to_run:
        print("[模型] 加载 ResNet-34 (ImageNet)...")
        import torchvision.models as tv_models
        r34 = tv_models.resnet34(weights=tv_models.ResNet34_Weights.IMAGENET1K_V1)
        r34.fc = torch.nn.Identity(); r34.eval()
        tf_res = transforms.Compose([
            transforms.Resize((224, 224)), transforms.Grayscale(3), transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])
        models["resnet34"] = (r34, tf_res)

    # ── 对每个方法运行测试 ─────────────────────────────────────────────────
    for method_name in methods_to_run:
        print(f"\n{'='*60}")
        print(f"  方法: {method_name.upper()}")
        print(f"{'='*60}")

        feat_dir   = os.path.join(BASE_DIR, "fingerprint_features")
        result_dir = os.path.join(BASE_DIR, "results", f"hq_{args.dataset}_{method_name}")
        os.makedirs(feat_dir, exist_ok=True)
        os.makedirs(result_dir, exist_ok=True)

        # 提取特征
        key_map = {}  # (user, sample_tag) → key_name
        for u, samples in dataset.items():
            for idx, (tag, path) in enumerate(samples):
                key = f"{u}_{idx+1}"
                key_map[(u, tag, idx)] = key
                out = os.path.join(feat_dir, f"{key}_vault.dat")
                if method_name == "dinov2":
                    m, proj, tf = models["dinov2"]
                    feat = extract_dinov2(m, proj, tf, path)
                else:
                    r34, tf = models["resnet34"]
                    feat = extract_resnet34(r34, tf, path)
                if feat is not None:
                    feat.tofile(out)

        # 生成 CSV
        users = sorted(dataset.keys())
        rows  = []
        # Genuine: 同一用户的所有样本对
        for u in users:
            n = len(dataset[u])
            for i in range(1, n+1):
                for j in range(i+1, n+1):
                    rows.append(["Genuine", f"{u}_{i}_vault", f"{u}_{j}_vault", 0])
        # Impostor: 一个用户的第1个样本 vs 其他用户的第1个样本
        for u1 in users:
            for u2 in users:
                if u1 == u2: continue
                rows.append(["Impostor", f"{u1}_1_vault", f"{u2}_1_vault", 0])

        csv_path = os.path.join(BASE_DIR, "unified_test_plan_vault.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f); w.writerow(["Type","Template","Probe","ErrorBits"]); w.writerows(rows)

        gen_n = sum(1 for r in rows if r[0]=="Genuine")
        imp_n = sum(1 for r in rows if r[0]=="Impostor")
        print(f"  测试对数: Genuine={gen_n}, Impostor={imp_n}")

        # 运行测试
        result = subprocess.run(["./test_batch_vault"],
                                cwd=os.path.join(BASE_DIR, "build"),
                                capture_output=True, text=True)
        print(result.stdout)

        # 保存
        with open(os.path.join(result_dir, "test_result.txt"), "w") as f:
            f.write(result.stdout)
        shutil.copy(csv_path, os.path.join(result_dir, "unified_test_plan_vault.csv"))
        feat_save = os.path.join(result_dir, "fingerprint_features")
        if os.path.exists(feat_save): shutil.rmtree(feat_save)
        shutil.copytree(feat_dir, feat_save)
        print(f"  结果已保存到 {result_dir}")


if __name__ == "__main__":
    main()
