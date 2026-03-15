#!/usr/bin/env python3
"""
性能基准测试脚本
用于自动化测试协议性能并生成论文数据
"""

import requests
import time
import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

SERVER_URL = "http://127.0.0.1:8081"

def test_registration_performance(num_tests=10):
    """测试注册阶段性能"""
    print(f"\n{'='*60}")
    print(f"开始注册性能测试 (n={num_tests})")
    print(f"{'='*60}\n")

    times = []
    for i in range(num_tests):
        uid = f"perf_test_user_{i}"

        # 模拟注册请求（简化版，实际需要完整的密钥生成）
        payload = {
            "uid": uid,
            "avk_pkSig": "04" + "00" * 64,  # 模拟公钥
            "avk_skEnc": "00" * 32  # 模拟私钥
        }

        start = time.time()
        try:
            resp = requests.post(f"{SERVER_URL}/api/register", json=payload, timeout=5)
            elapsed = (time.time() - start) * 1000  # 转换为毫秒

            if resp.status_code == 200:
                times.append(elapsed)
                print(f"  测试 {i+1}/{num_tests}: {elapsed:.2f} ms ✓")
            else:
                print(f"  测试 {i+1}/{num_tests}: 失败 - {resp.text}")
        except Exception as e:
            print(f"  测试 {i+1}/{num_tests}: 异常 - {e}")

    if times:
        print(f"\n注册性能统计:")
        print(f"  平均值: {np.mean(times):.2f} ms")
        print(f"  标准差: {np.std(times):.2f} ms")
        print(f"  最小值: {np.min(times):.2f} ms")
        print(f"  最大值: {np.max(times):.2f} ms")
        print(f"  中位数: {np.median(times):.2f} ms")

    return times

def export_performance_report():
    """导出性能报告"""
    print(f"\n{'='*60}")
    print("导出性能报告")
    print(f"{'='*60}\n")

    try:
        resp = requests.get(f"{SERVER_URL}/api/performance/export", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"✓ 性能报告已导出: {data['file']}")
            return data['file']
        else:
            print(f"✗ 导出失败: {resp.text}")
    except Exception as e:
        print(f"✗ 异常: {e}")

    return None

def visualize_performance(csv_file="performance_report.csv"):
    """可视化性能数据"""
    print(f"\n{'='*60}")
    print("生成性能可视化图表")
    print(f"{'='*60}\n")

    try:
        df = pd.read_csv(csv_file)

        # 图 1: 密码学操作耗时（微秒）
        crypto_ops = df[df['Unit'] == 'us'].head(9)
        if not crypto_ops.empty:
            plt.figure(figsize=(10, 6))
            plt.barh(crypto_ops['Metric'], crypto_ops['Value'], color='#58a6ff')
            plt.xlabel('耗时 (μs)', fontsize=12)
            plt.title('密码学原语性能对比', fontsize=14, fontweight='bold')
            plt.tight_layout()
            plt.savefig('crypto_operations_performance.png', dpi=300, bbox_inches='tight')
            print("✓ 已生成: crypto_operations_performance.png")
            plt.close()

        # 图 2: 协议阶段耗时（毫秒）
        protocol_phases = df[df['Unit'] == 'ms']
        if not protocol_phases.empty:
            plt.figure(figsize=(8, 5))
            plt.bar(protocol_phases['Metric'], protocol_phases['Value'], color='#3fb950')
            plt.ylabel('耗时 (ms)', fontsize=12)
            plt.title('协议阶段性能分析', fontsize=14, fontweight='bold')
            plt.xticks(rotation=15, ha='right')
            plt.tight_layout()
            plt.savefig('protocol_phases_performance.png', dpi=300, bbox_inches='tight')
            print("✓ 已生成: protocol_phases_performance.png")
            plt.close()

        # 图 3: 认证统计饼图
        auth_stats = df[df['Unit'] == 'count']
        if len(auth_stats) >= 2:
            success = auth_stats[auth_stats['Metric'] == 'Successful Auths']['Value'].values[0]
            failed = auth_stats[auth_stats['Metric'] == 'Failed Auths']['Value'].values[0]

            if success + failed > 0:
                plt.figure(figsize=(7, 7))
                plt.pie([success, failed], labels=['成功', '失败'],
                       autopct='%1.1f%%', colors=['#3fb950', '#f85149'],
                       startangle=90, textprops={'fontsize': 12})
                plt.title('认证成功率分布', fontsize=14, fontweight='bold')
                plt.tight_layout()
                plt.savefig('auth_success_rate.png', dpi=300, bbox_inches='tight')
                print("✓ 已生成: auth_success_rate.png")
                plt.close()

        print("\n所有图表生成完毕！可用于论文插图。")

    except Exception as e:
        print(f"✗ 可视化失败: {e}")

def main():
    print("""
╔══════════════════════════════════════════════════════════╗
║   IoT 认证协议性能基准测试工具                           ║
║   Performance Benchmarking Tool                          ║
╚══════════════════════════════════════════════════════════╝
    """)

    # 测试 1: 注册性能
    reg_times = test_registration_performance(num_tests=10)

    # 等待一下让服务器处理完
    time.sleep(2)

    # 导出性能报告
    report_file = export_performance_report()

    # 可视化
    if report_file:
        visualize_performance(report_file)

    print(f"\n{'='*60}")
    print("测试完成！")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()
