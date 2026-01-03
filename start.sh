#!/bin/bash

echo "🚀 [1/2] 正在启动 C++ IoT 认证网关 (后端)..."
# 假设你的可执行文件在 build 目录下
./build/iot_gateway_server &
BACKEND_PID=$! # 记录后端的进程 ID

echo "🎨 [2/2] 正在启动 Vue 交互界面 (前端)..."
# 假设你的前端位于根目录，或者在特定的 frontend 文件夹中
# 如果在子文件夹，可以改成：cd frontend && npm run dev &
cd web && npm run dev &
FRONTEND_PID=$! # 记录前端的进程 ID

echo "✅ 所有服务已启动！后端 PID: $BACKEND_PID, 前端 PID: $FRONTEND_PID"
echo "🛑 按 Ctrl+C 即可一键安全关闭所有服务。"

# 核心魔法：捕获 Ctrl+C (SIGINT) 信号，优雅地杀死这两个后台进程
trap "echo ' 正在关闭服务...'; kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT

# 挂起主脚本，等待后台任务运行
wait