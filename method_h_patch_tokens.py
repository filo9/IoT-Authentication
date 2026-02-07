"""
Method H: DINOv2 Patch Tokens (98304→512) — 局部特征
================================================================
原理：
  DINOv2 ViT-S/14 对 224×224 图像产生 16×16=256 个 patch token，
  每个 token 对应 14×14 像素区域（约 4mm² 的脊线纹路）。
  - CLS token（全局摘要）：不同用户的指纹全局相似 → 零差异碰撞多
  - Patch tokens（局部特征）：每个位置的脊线特征差异化 → 碰撞极少

参数：
  256 patch × 384 dim = 98304 维 → 固定随机投影 → 512 维特征
  之后走 BioModule RS(32,16) t=8 模糊承诺

预期：
  • Genuine bit_diff → 0-5 bits（变体极小）
  • Impostor bit_diff → >>8 bits（局部脊线特征差异大）
  • FAR → 0%，TAR → 接近100%
"""
import os, csv, shutil, subprocess, warnings, time
import cv2, numpy as np, torch
import torch.nn.functional as F
import torchvision.transforms as T
from PIL import Image

warnings.filterwarnings("ignore")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOC_ROOT = os.path.join(BASE_DIR, "socofing", "socofing", "SOCOFing")
FEAT_DIR = os.path.join(BASE_DIR, "fingerprint_features")
RES_DIR  = os.path.join(BASE_DIR, "results", "soc_method_h_patch_tokens")
os.makedirs(FEAT_DIR, exist_ok=True)
os.makedirs(RES_DIR, exist_ok=True)

FINGER   = "Left_index_finger"
MAX_SUBJ = 200

# ── 数据索引 ──────────────────────────────────────────────────────────────────
real_dir = os.path.join(SOC_ROOT, "Real")
easy_dir = os.path.join(SOC_ROOT, "Altered", "Altered-Easy")
dataset  = {}
for fname in sorted(os.listdir(real_dir)):
    if not fname.endswith(".BMP") or FINGER not in fname: continue
    sid = fname.split("__")[0]
    if int(sid) > MAX_SUBJ: continue
    base = fname.replace(".BMP", "")
    entries = [("real", os.path.join(real_dir, fname))]
    for s in ["CR", "Obl", "Zcut"]:
        p = os.path.join(easy_dir, f"{base}_{s}.BMP")
        if os.path.exists(p): entries.append((s, p))
    if len(entries) >= 2:
        dataset[sid] = entries

users = sorted(dataset.keys(), key=int)
print(f"[Method H] 受试者: {len(users)} 个")

# ── 模型初始化 ────────────────────────────────────────────────────────────────
print("[Method H] 加载 DINOv2 ViT-S/14...")
dino = torch.hub.load("facebookresearch/dinov2", "dinov2_vits14", verbose=False)
dino.eval()
N_PATCHES = 256         # 16×16 patches for 224×224 input with patch_size=14
DIM       = dino.embed_dim  # 384

# 固定随机投影：98304 → 512
np.random.seed(42)
proj = np.random.randn(N_PATCHES * DIM, 512).astype(np.float32)
proj /= np.linalg.norm(proj, axis=0, keepdims=True)

tf = T.Compose([
    T.Resize((224, 224)), T.Grayscale(3), T.ToTensor(),
    T.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
])


def extract(path):
    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None: return None
    clahe = cv2.createCLAHE(2.0, (8, 8)); img = clahe.apply(img)
    t = tf(Image.fromarray(img)).unsqueeze(0)
    with torch.no_grad():
        out = dino.get_intermediate_layers(t, n=1, return_class_token=True)[0]
        patches = out[0].squeeze(0).numpy().flatten()  # 256×384 = 98304
    feat = patches @ proj   # → 512
    feat = feat - feat.mean()
    return feat.astype(np.float32)


# ── 提取特征 ──────────────────────────────────────────────────────────────────
print("[Method H] 提取 patch token 特征...")
t0 = time.time()
ok = 0
for sid in users:
    for idx, (tag, path) in enumerate(dataset[sid]):
        out = os.path.join(FEAT_DIR, f"{sid}_{idx+1}_vault.dat")
        feat = extract(path)
        if feat is not None:
            feat.tofile(out); ok += 1
print(f"[Method H] 提取完毕: {ok} 份, 耗时 {time.time()-t0:.0f}s")

# ── 分析比特差异分布（验证 FAR=0% 的可行性）────────────────────────────────
print("\n[Method H] 分析比特差异分布...")
feats = {}
for f in os.listdir(FEAT_DIR):
    if not f.endswith("_vault.dat"): continue
    parts = f.replace("_vault.dat","").split("_")
    u, i = parts[0], int(parts[1])
    data = np.frombuffer(open(os.path.join(FEAT_DIR,f),"rb").read(), dtype=np.float32)
    if u not in feats: feats[u] = {}
    feats[u][i] = data

rng = np.random.default_rng(42)
gen_bits, imp_bits = [], []
for u in users:
    ref = feats[u][1]; idx256 = np.argsort(-np.abs(ref))[:256]
    rb = (ref[idx256] > 0).astype(int)
    for i in feats[u]:
        if i == 1: continue
        pb = (feats[u][i][idx256] > 0).astype(int)
        gen_bits.append(int(np.sum(rb != pb)))
for i, u1 in enumerate(users):
    for u2 in users[i+1:]:
        ref = feats[u1][1]; idx256 = np.argsort(-np.abs(ref))[:256]
        rb = (ref[idx256]>0).astype(int)
        pb = (feats[u2][1][idx256]>0).astype(int)
        imp_bits.append(int(np.sum(rb != pb)))

gb = np.array(gen_bits); ib = np.array(imp_bits)
print(f"Genuine:  min={gb.min()} mean={gb.mean():.1f} max={gb.max()}")
print(f"Impostor: min={ib.min()} mean={ib.mean():.1f} max={ib.max()}")
print(f"零差异冒充对: {np.sum(ib==0)}")

# 对每个 t 值预测 TAR/FAR
print("\n不同 RS 参数预测效果:")
for t_val in [8, 12, 16, 20]:
    tar = np.mean(gb <= t_val) * 100
    far = np.mean(ib <= t_val) * 100
    print(f"  t={t_val:2d}: TAR≈{tar:.1f}%  FAR≈{far:.1f}%")

# ── 生成 CSV + 运行测试 ───────────────────────────────────────────────────────
rows = []
for u in users:
    n = len(dataset[u])
    for i in range(1, n+1):
        for j in range(i+1, n+1):
            rows.append(["Genuine", f"{u}_{i}_vault", f"{u}_{j}_vault", 0])
for i, u1 in enumerate(users):
    for u2 in users[i+1:]:
        rows.append(["Impostor", f"{u1}_1_vault", f"{u2}_1_vault", 0])

csv_path = os.path.join(BASE_DIR, "unified_test_plan_vault.csv")
with open(csv_path, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["Type","Template","Probe","ErrorBits"]); w.writerows(rows)

gen_n = sum(1 for r in rows if r[0]=="Genuine")
imp_n = sum(1 for r in rows if r[0]=="Impostor")
print(f"\n测试规模: Genuine={gen_n}, Impostor={imp_n}")

result = subprocess.run(["./test_batch_vault"], cwd=os.path.join(BASE_DIR,"build"),
                        capture_output=True, text=True)
print(result.stdout)

# ── 保存结果 ──────────────────────────────────────────────────────────────────
with open(os.path.join(RES_DIR,"test_result.txt"),"w") as f: f.write(result.stdout)
shutil.copy(csv_path, os.path.join(RES_DIR,"unified_test_plan_vault.csv"))
feat_save = os.path.join(RES_DIR,"fingerprint_features")
if os.path.exists(feat_save): shutil.rmtree(feat_save)
shutil.copytree(FEAT_DIR, feat_save)

# 恢复默认
subprocess.run(["python3","-W","ignore","extract_fvc_resnet.py"],
               cwd=BASE_DIR, capture_output=True)
print(f"\n[Method H] 结果已保存 → {RES_DIR}")
