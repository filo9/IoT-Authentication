"""
Method A: ResNet-34 直接提取真实 FVC2002 指纹图像特征（Baseline）
特点：不做任何指纹专用预处理，直接用 ImageNet 预训练权重
预期：TAR 低（~20%），FAR 低，用于论文中说明问题所在
"""
import os, csv, shutil, subprocess
import torch, torchvision.models as models, torchvision.transforms as transforms
import torch.nn.functional as F
import numpy as np
from PIL import Image, ImageOps

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
IMG_DIR    = os.path.join(BASE_DIR, "fvc2002_db1")
FEAT_DIR   = os.path.join(BASE_DIR, "fingerprint_features")
RESULT_DIR = os.path.join(BASE_DIR, "results", "method_a_resnet34")
os.makedirs(FEAT_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)

USERS   = [str(i) for i in range(101, 111)]
SAMPLES = list(range(1, 9))  # FVC2002 DB1: 8 samples per user

# ── 模型 ────────────────────────────────────────────────────────────────────
print("[Method A] 加载 ResNet-34 (ImageNet pretrained)...")
model = models.resnet34(weights=models.ResNet34_Weights.IMAGENET1K_V1)
model.fc = torch.nn.Identity()
model.eval()

transform = transforms.Compose([
    transforms.Lambda(lambda img: ImageOps.autocontrast(img)),
    transforms.CenterCrop((300, 300)),
    transforms.Resize((224, 224)),
    transforms.Grayscale(num_output_channels=3),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])

# ── 特征提取 ─────────────────────────────────────────────────────────────────
print("[Method A] 从真实图像提取特征...")
count = 0
with torch.no_grad():
    for u in USERS:
        for i in SAMPLES:
            img_path = os.path.join(IMG_DIR, f"{u}_{i}.tif")
            out_path = os.path.join(FEAT_DIR, f"{u}_{i}_vault.dat")
            if not os.path.exists(img_path):
                continue
            img  = Image.open(img_path)
            t    = transform(img).unsqueeze(0)
            feat = model(t)
            feat = F.normalize(feat, p=2, dim=1).squeeze().numpy()
            feat = feat - feat.mean()
            feat.astype(np.float32).tofile(out_path)
            count += 1

print(f"[Method A] 提取完毕：{count} 份特征")

# ── CSV ───────────────────────────────────────────────────────────────────────
csv_path = os.path.join(BASE_DIR, "unified_test_plan_vault.csv")
rows = []
for u in USERS:
    for i in SAMPLES:
        for j in range(i + 1, 9):
            rows.append(["Genuine", f"{u}_{i}_vault", f"{u}_{j}_vault", 0])
for u1 in USERS:
    for i in SAMPLES:
        for u2 in USERS:
            if u1 == u2:
                continue
            rows.append(["Impostor", f"{u1}_{i}_vault", f"{u2}_1_vault", 0])

with open(csv_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["Type", "Template", "Probe", "ErrorBits"])
    w.writerows(rows)
print(f"[Method A] CSV 生成完毕 (Genuine={sum(1 for r in rows if r[0]=='Genuine')}, "
      f"Impostor={sum(1 for r in rows if r[0]=='Impostor')})")

# ── 运行测试 ──────────────────────────────────────────────────────────────────
print("[Method A] 运行 test_batch_vault...")
result = subprocess.run(
    ["./test_batch_vault"], cwd=os.path.join(BASE_DIR, "build"),
    capture_output=True, text=True
)
print(result.stdout)
if result.returncode != 0:
    print("STDERR:", result.stderr[:300])

# ── 保存结果 ──────────────────────────────────────────────────────────────────
with open(os.path.join(RESULT_DIR, "test_result.txt"), "w") as f:
    f.write(result.stdout)
shutil.copy(csv_path, os.path.join(RESULT_DIR, "unified_test_plan_vault.csv"))
feat_save = os.path.join(RESULT_DIR, "fingerprint_features")
if os.path.exists(feat_save):
    shutil.rmtree(feat_save)
shutil.copytree(FEAT_DIR, feat_save)
print(f"[Method A] 结果已保存到 {RESULT_DIR}")
