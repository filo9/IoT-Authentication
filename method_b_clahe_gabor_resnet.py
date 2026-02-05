"""
Method B: CLAHE + Gabor 增强 + ResNet-34
特点：加入指纹专用预处理（CLAHE 对比度均衡 + Gabor 脊线增强）
预期：TAR 约 40-60%，FAR 低，论文中作为"预处理改善"对比组
"""
import os, csv, shutil, subprocess
import cv2
import torch, torchvision.models as models, torchvision.transforms as transforms
import torch.nn.functional as F
import numpy as np
from PIL import Image

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
IMG_DIR    = os.path.join(BASE_DIR, "fvc2002_db1")
FEAT_DIR   = os.path.join(BASE_DIR, "fingerprint_features")
RESULT_DIR = os.path.join(BASE_DIR, "results", "method_b_clahe_gabor_resnet")
os.makedirs(FEAT_DIR, exist_ok=True)
os.makedirs(RESULT_DIR, exist_ok=True)

USERS   = [str(i) for i in range(101, 111)]
SAMPLES = list(range(1, 9))

# ── 指纹专用预处理 ──────────────────────────────────────────────────────────
def preprocess_fingerprint(img_path):
    img = cv2.imread(img_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None
    # 1. CLAHE：局部对比度均衡（指纹增强标准操作）
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
    img   = clahe.apply(img)
    # 2. 多方向 Gabor 滤波器组，提取脊线响应（4 个方向）
    gabor_sum = np.zeros_like(img, dtype=np.float32)
    for theta in [0, np.pi / 4, np.pi / 2, 3 * np.pi / 4]:
        kernel = cv2.getGaborKernel((31, 31), sigma=4.0, theta=theta,
                                    lambd=10.0, gamma=0.5, psi=0)
        gabor_sum += np.abs(cv2.filter2D(img.astype(np.float32), -1, kernel))
    img = (gabor_sum / gabor_sum.max() * 255).astype(np.uint8)
    return Image.fromarray(img)

# ── 模型 ────────────────────────────────────────────────────────────────────
print("[Method B] 加载 ResNet-34 (ImageNet pretrained)...")
model = models.resnet34(weights=models.ResNet34_Weights.IMAGENET1K_V1)
model.fc = torch.nn.Identity()
model.eval()

transform = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.Grayscale(num_output_channels=3),
    transforms.ToTensor(),
    transforms.Normalize(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225]),
])

# ── 特征提取 ─────────────────────────────────────────────────────────────────
print("[Method B] CLAHE + Gabor 预处理后提取特征...")
count = 0
with torch.no_grad():
    for u in USERS:
        for i in SAMPLES:
            img_path = os.path.join(IMG_DIR, f"{u}_{i}.tif")
            out_path = os.path.join(FEAT_DIR, f"{u}_{i}_vault.dat")
            if not os.path.exists(img_path):
                continue
            pil  = preprocess_fingerprint(img_path)
            if pil is None:
                continue
            t    = transform(pil).unsqueeze(0)
            feat = model(t)
            feat = F.normalize(feat, p=2, dim=1).squeeze().numpy()
            feat = feat - feat.mean()
            feat.astype(np.float32).tofile(out_path)
            count += 1

print(f"[Method B] 提取完毕：{count} 份特征")

# ── CSV + 测试 + 保存（复用逻辑）────────────────────────────────────────────
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

result = subprocess.run(
    ["./test_batch_vault"], cwd=os.path.join(BASE_DIR, "build"),
    capture_output=True, text=True
)
print(result.stdout)

with open(os.path.join(RESULT_DIR, "test_result.txt"), "w") as f:
    f.write(result.stdout)
shutil.copy(csv_path, os.path.join(RESULT_DIR, "unified_test_plan_vault.csv"))
feat_save = os.path.join(RESULT_DIR, "fingerprint_features")
if os.path.exists(feat_save):
    shutil.rmtree(feat_save)
shutil.copytree(FEAT_DIR, feat_save)
print(f"[Method B] 结果已保存到 {RESULT_DIR}")
