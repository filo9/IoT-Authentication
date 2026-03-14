"""
SOCOfing 数据集 — 全方法批量测试
================================================================
数据集配置：
  - 600 受试者 × 左食指（1 Real + 3 Easy 变体）
  - Genuine 对: Real vs CR / Real vs Obl / Real vs Zcut
  - Impostor 对: 不同受试者的 Real 图互比

测试方法：
  A. ResNet-34 (CLAHE)
  B. CLAHE + Gabor + ResNet-34
  C. Gabor IrisCode（幅度）
  D. DINOv2 ViT-S/14
  E. Minutiae HOG
  F. Gabor 相位编码
"""
import os, csv, shutil, subprocess, warnings, time
import cv2, numpy as np, torch
import torch.nn.functional as F
import torchvision.models as tv_models
import torchvision.transforms as transforms
from PIL import Image

warnings.filterwarnings("ignore")
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
SOC_ROOT  = os.path.join(BASE_DIR, "socofing", "socofing", "SOCOFing")
FEAT_DIR  = os.path.join(BASE_DIR, "fingerprint_features")
RES_DIR   = os.path.join(BASE_DIR, "results")
FINGER    = "Left_index_finger"
MAX_SUBJ  = 200   # 用前 200 个受试者（Genuine=600对，Impostor=39800对）

os.makedirs(FEAT_DIR, exist_ok=True)
os.makedirs(RES_DIR, exist_ok=True)

# ── 构建数据集索引 ────────────────────────────────────────────────────────────
real_dir = os.path.join(SOC_ROOT, "Real")
easy_dir = os.path.join(SOC_ROOT, "Altered", "Altered-Easy")

all_subjects = sorted(
    set(f.split("__")[0] for f in os.listdir(real_dir) if f.endswith(".BMP")),
    key=lambda x: int(x)
)[:MAX_SUBJ]

print(f"[SOCOfing] 受试者: {len(all_subjects)} 个，手指: {FINGER}")

# 每个受试者: Real + 3 Easy 变体
dataset = {}
for sid in all_subjects:
    real_path = os.path.join(real_dir, f"{sid}__{sid.split('__')[-1]}{FINGER}.BMP"
                             if "__" in sid else f"{sid}__M_{FINGER}.BMP")
    # 匹配含 M 或 F 性别标记的文件名
    real_files = [f for f in os.listdir(real_dir)
                  if f.startswith(f"{sid}__") and FINGER in f]
    if not real_files:
        continue
    real_path = os.path.join(real_dir, real_files[0])
    base_name = real_files[0].replace(".BMP", "")

    entries = [("real", real_path)]
    for suffix in ["CR", "Obl", "Zcut"]:
        alt = os.path.join(easy_dir, f"{base_name}_{suffix}.BMP")
        if os.path.exists(alt):
            entries.append((suffix, alt))
    if len(entries) >= 2:
        dataset[sid] = entries

print(f"[SOCOfing] 有效受试者: {len(dataset)}（含 Easy 变体）")


# ── 生成 CSV ─────────────────────────────────────────────────────────────────
def make_csv(users):
    rows = []
    # Genuine: Real vs 每个 Easy 变体
    for sid in users:
        samples = dataset[sid]
        for i in range(1, len(samples)):   # 索引 1+ 是变体
            rows.append(["Genuine", f"{sid}_1_vault", f"{sid}_{i+1}_vault", 0])
    # Impostor: 不同受试者的 Real 对比
    for i, u1 in enumerate(users):
        for u2 in users[i+1:]:
            rows.append(["Impostor", f"{u1}_1_vault", f"{u2}_1_vault", 0])
    return rows


# ── 特征提取器 ────────────────────────────────────────────────────────────────
class ResNet34Extractor:
    def __init__(self, use_gabor=False):
        self.use_gabor = use_gabor
        model = tv_models.resnet34(weights=tv_models.ResNet34_Weights.IMAGENET1K_V1)
        model.fc = torch.nn.Identity(); model.eval()
        self.model = model
        self.tf = transforms.Compose([
            transforms.Resize((224,224)), transforms.Grayscale(3), transforms.ToTensor(),
            transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])
        ])
    def __call__(self, path):
        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None: return None
        clahe = cv2.createCLAHE(2.0, (8,8)); img = clahe.apply(img)
        if self.use_gabor:
            g = np.zeros_like(img, dtype=np.float32)
            for th in [0, np.pi/4, np.pi/2, 3*np.pi/4]:
                k = cv2.getGaborKernel((31,31), 4.0, th, 10.0, 0.5, 0)
                g += np.abs(cv2.filter2D(img.astype(np.float32), -1, k))
            img = (g/g.max()*255).astype(np.uint8)
        pil = Image.fromarray(img)
        with torch.no_grad():
            f = self.model(self.tf(pil).unsqueeze(0))
            f = F.normalize(f,p=2,dim=1).squeeze().numpy()
        f = f - f.mean(); return f.astype(np.float32)


class DINOv2Extractor:
    def __init__(self):
        model = torch.hub.load("facebookresearch/dinov2","dinov2_vits14",verbose=False)
        model.eval(); self.model = model
        np.random.seed(42)
        proj = np.random.randn(model.embed_dim,512).astype(np.float32)
        proj /= np.linalg.norm(proj, axis=0, keepdims=True)
        self.proj = proj
        self.tf = transforms.Compose([
            transforms.Resize((224,224)), transforms.Grayscale(3), transforms.ToTensor(),
            transforms.Normalize([0.485,0.456,0.406],[0.229,0.224,0.225])
        ])
    def __call__(self, path):
        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None: return None
        clahe = cv2.createCLAHE(2.0,(8,8)); img = clahe.apply(img)
        pil = Image.fromarray(img)
        with torch.no_grad():
            f = self.model(self.tf(pil).unsqueeze(0))
            f = F.normalize(f,p=2,dim=1).squeeze().numpy()
        f = f @ self.proj; f = f - f.mean(); return f.astype(np.float32)


BLOCK, ROI = 16, 160

def orient_field(img, block=BLOCK):
    gx = cv2.Sobel(img.astype(np.float64), cv2.CV_64F, 1, 0, ksize=3)
    gy = cv2.Sobel(img.astype(np.float64), cv2.CV_64F, 0, 1, ksize=3)
    Vx, Vy = 2*gx*gy, gx**2-gy**2
    h, w = img.shape; bh, bw = max(1,h//block), max(1,w//block)
    o = np.zeros((bh,bw)); c = np.zeros((bh,bw))
    for i in range(bh):
        for j in range(bw):
            vx = Vx[i*block:min((i+1)*block,h), j*block:min((j+1)*block,w)].sum()
            vy = Vy[i*block:min((i+1)*block,h), j*block:min((j+1)*block,w)].sum()
            o[i,j] = np.arctan2(vx,vy)/2; c[i,j] = np.sqrt(vx**2+vy**2)
    return o, c

def poincare(o, i, j):
    h, w = o.shape
    if i<1 or i>=h-1 or j<1 or j>=w-1: return 0
    nb=[o[i-1,j-1],o[i-1,j],o[i-1,j+1],o[i,j+1],o[i+1,j+1],o[i+1,j],o[i+1,j-1],o[i,j-1],o[i-1,j-1]]
    s=0.0
    for k in range(8):
        d=nb[k+1]-nb[k]
        while d>np.pi/2: d-=np.pi
        while d<-np.pi/2: d+=np.pi
        s+=d
    return round(s/np.pi)

def find_core(img):
    o, c = orient_field(img); bh, bw = o.shape
    cores = [(i,j,c[max(0,i-2):i+3,max(0,j-2):j+3].mean())
             for i in range(1,bh-1) for j in range(1,bw-1) if poincare(o,i,j)==1]
    if cores:
        cores.sort(key=lambda x:-x[2]); ci,cj = cores[0][0],cores[0][1]
    else:
        ct=np.percentile(c,70); mask=c>ct
        if not mask.any(): return img.shape[0]//2, img.shape[1]//2, 0.0
        ys,xs=np.where(mask); ci,cj=int(ys.mean()),int(xs.mean())
    cy,cx=ci*BLOCK+BLOCK//2, cj*BLOCK+BLOCK//2
    i0,i1=max(0,ci-2),min(bh,ci+3); j0,j1=max(0,cj-2),min(bw,cj+3)
    lo=o[i0:i1,j0:j1].flatten(); lc=c[i0:i1,j0:j1].flatten(); w_=lc/(lc.sum()+1e-9)
    main=np.arctan2((np.sin(2*lo)*w_).sum(),(np.cos(2*lo)*w_).sum())/2
    return cy,cx,main

def align_crop(img):
    h,w=img.shape; cy,cx,ang=find_core(img)
    M=cv2.getRotationMatrix2D((cx,cy),np.degrees(ang),1.0)
    al=cv2.warpAffine(img,M,(w,h),flags=cv2.INTER_LINEAR,borderMode=cv2.BORDER_REFLECT)
    half=ROI//2
    pl=max(0,half-cx); pr=max(0,cx+half-w)
    pt=max(0,half-cy); pb=max(0,cy+half-h)
    pad=cv2.copyMakeBorder(al,pt,pb,pl,pr,cv2.BORDER_REFLECT)
    return pad[cy-half+pt:cy+half+pt, cx-half+pl:cx+half+pl]

class GaborIriscode:
    """Method C: Gabor 幅度（奇异点对齐）"""
    def __call__(self, path):
        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None: return None
        clahe = cv2.createCLAHE(2.0,(8,8)); img = clahe.apply(img)
        roi = align_crop(img); roi = cv2.resize(roi,(ROI,ROI))
        feats=[]
        for th in [0.,np.pi/4,np.pi/2,3*np.pi/4]:
            for lm in [6.,12.]:
                k=cv2.getGaborKernel((31,31),4.,th,lm,.5,0)
                r=np.abs(cv2.filter2D(roi.astype(np.float32),-1,k))
                feats.append(cv2.resize(r,(8,8)).flatten())
        f=np.concatenate(feats); f=f-f.mean(); return f.astype(np.float32)

class GaborPhase:
    """Method F: Gabor 相位编码"""
    def __call__(self, path):
        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None: return None
        clahe = cv2.createCLAHE(2.0,(8,8)); img = clahe.apply(img)
        roi = align_crop(img); roi = cv2.resize(roi.astype(np.float32),(ROI,ROI))
        feats=[]
        for th in [0.,np.pi/4,np.pi/2,3*np.pi/4]:
            for lm in [6.,12.]:
                k=cv2.getGaborKernel((31,31),4.,th,lm,.5,psi=0)
                r=cv2.filter2D(roi,-1,k)  # 实部（含符号）
                feats.append(cv2.resize(r,(8,8)).flatten())
        f=np.concatenate(feats); f=f-f.mean(); return f.astype(np.float32)

class MinutiaeHOG:
    """Method E: 细节点 HOG"""
    def __call__(self, path):
        import fingerprint_enhancer, fingerprint_feature_extractor
        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None: return None
        # SOCOfing 图较小，先放大再处理
        img = cv2.resize(img, (388, 374))
        try:
            skel = np.array(fingerprint_enhancer.enhance_fingerprint(img)).astype(np.uint8)*255
            FT,FB = fingerprint_feature_extractor.extract_minutiae_features(
                skel, spuriousMinutiaeThresh=10, invertImage=False, showResult=False, saveResult=False)
        except Exception:
            FT, FB = [], []
        minutiae = []
        for m in FT:
            ang = m.Orientation[0] if isinstance(m.Orientation, (list,np.ndarray)) else m.Orientation
            minutiae.append((m.locX, m.locY, float(ang)))
        for m in FB:
            ang = m.Orientation[0] if isinstance(m.Orientation, (list,np.ndarray)) else m.Orientation
            minutiae.append((m.locX, m.locY, float(ang)))
        if len(minutiae) < 5:
            return self._fallback(img)
        angles = np.array([m[2] for m in minutiae])
        main = np.arctan2(np.sin(angles).mean(), np.cos(angles).mean())
        GRID, BINS = 8, 8
        hist = np.zeros((GRID,GRID,BINS), dtype=np.float32)
        for mx,my,ang in minutiae:
            rel = (ang-main)%(2*np.pi); b = int(rel/(2*np.pi)*BINS)%BINS
            ci = min(int(my/374*GRID),GRID-1); cj = min(int(mx/388*GRID),GRID-1)
            hist[ci,cj,b] += 1.
        f = hist.flatten()
        nm = np.linalg.norm(f); f = f/nm if nm>1e-8 else f
        f = f-f.mean(); return f.astype(np.float32)
    def _fallback(self, img):
        clahe = cv2.createCLAHE(2.0,(8,8)); img = clahe.apply(img)
        parts=[]
        for th in [0.,np.pi/4,np.pi/2,3*np.pi/4]:
            for lm in [6.,12.]:
                k=cv2.getGaborKernel((31,31),4.,th,lm,.5,0)
                r=np.abs(cv2.filter2D(img.astype(np.float32),-1,k))
                parts.append(cv2.resize(r,(8,8)).flatten())
        f=np.concatenate(parts); f=f-f.mean(); return f.astype(np.float32)


# ── 测试流程 ──────────────────────────────────────────────────────────────────
def run_method(name, extractor, users):
    print(f"\n{'='*55}")
    print(f"  [{name}] 提取特征中...")
    t0 = time.time()

    ok = 0
    for sid in users:
        for idx, (tag, path) in enumerate(dataset[sid]):
            out = os.path.join(FEAT_DIR, f"{sid}_{idx+1}_vault.dat")
            feat = extractor(path)
            if feat is not None:
                feat.tofile(out); ok += 1

    rows = make_csv(users)
    csv_path = os.path.join(BASE_DIR, "unified_test_plan_vault.csv")
    with open(csv_path,"w",newline="") as f:
        w=csv.writer(f); w.writerow(["Type","Template","Probe","ErrorBits"]); w.writerows(rows)

    gen_n = sum(1 for r in rows if r[0]=="Genuine")
    imp_n = sum(1 for r in rows if r[0]=="Impostor")
    print(f"  特征: {ok} 份  Genuine: {gen_n}  Impostor: {imp_n}  耗时: {time.time()-t0:.0f}s")

    result = subprocess.run(["./test_batch_vault"], cwd=os.path.join(BASE_DIR,"build"),
                            capture_output=True, text=True)
    print(result.stdout)

    res_dir = os.path.join(RES_DIR, f"socofing_{name.lower().replace(' ','_').replace('+','_')}")
    os.makedirs(res_dir, exist_ok=True)
    with open(os.path.join(res_dir,"test_result.txt"),"w") as f: f.write(result.stdout)
    shutil.copy(csv_path, os.path.join(res_dir,"unified_test_plan_vault.csv"))
    feat_save = os.path.join(res_dir,"fingerprint_features")
    if os.path.exists(feat_save): shutil.rmtree(feat_save)
    shutil.copytree(FEAT_DIR, feat_save)
    return res_dir


# ── 初始化模型 ────────────────────────────────────────────────────────────────
users = sorted(dataset.keys(), key=lambda x: int(x))[:MAX_SUBJ]
users = [u for u in users if u in dataset]

print(f"\n[初始化] 加载模型...")
extractors = {
    "Method_A_ResNet34":   ResNet34Extractor(use_gabor=False),
    "Method_B_CLAHE_Gabor_ResNet": ResNet34Extractor(use_gabor=True),
    "Method_C_Gabor_IrisCode": GaborIriscode(),
    "Method_D_DINOv2":     DINOv2Extractor(),
    "Method_E_Minutiae":   MinutiaeHOG(),
    "Method_F_Gabor_Phase": GaborPhase(),
}

# ── 依次运行 ──────────────────────────────────────────────────────────────────
for name, extractor in extractors.items():
    run_method(name, extractor, users)

# 恢复默认
subprocess.run(["python3","-W","ignore","extract_fvc_resnet.py"],
               cwd=BASE_DIR, capture_output=True)
print("\n✅ 全部完成！结果在 results/socofing_*/ 目录")
