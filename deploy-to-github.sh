#!/bin/bash
# 快速部署脚本 - 将代码推送到 GitHub 仓库

# 设置 GitHub 仓库地址
GITHUB_REPO="https://github.com/youyao666/rust-"

echo "=== Trojan-Rust 快速部署脚本 ==="
echo ""

# 检查是否已初始化 git
if [ ! -d ".git" ]; then
    echo "初始化 Git 仓库..."
    git init
fi

# 添加所有文件
echo "添加所有文件到 Git..."
git add .

# 提交
echo "提交更改..."
git commit -m "Initial commit: Trojan-Rust with XTLS-Reality support"

# 设置默认分支为 main
git branch -M main

# 添加远程仓库（如果已存在则先移除）
if git remote | grep -q "^origin$"; then
    git remote remove origin
fi

echo "添加远程仓库：$GITHUB_REPO"
git remote add origin $GITHUB_REPO

# 推送到 GitHub
echo "推送到 GitHub..."
git push -u origin main

echo ""
echo "=== 推送完成！ ==="
echo ""
echo "下一步操作："
echo "1. 访问 GitHub 仓库查看代码：$GITHUB_REPO"
echo "2. 等待 GitHub Actions 自动构建 Docker 镜像"
echo "3. 镜像地址：ghcr.io/youyao666/rust-:latest"
echo ""
echo "部署到服务器："
echo "  docker pull ghcr.io/youyao666/rust-:latest"
echo "  docker-compose up -d"
