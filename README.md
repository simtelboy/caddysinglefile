# Caddy Single File Forward Proxy

一个基于 Caddy v2 的单文件前向代理解决方案，集成了用户管理、流量统计、Web管理界面等功能。

## 特性

- 🚀 **单文件部署**: 所有必要文件都嵌入在二进制文件中
- 🔐 **用户管理**: 完整的用户认证和管理系统
- 📊 **流量统计**: 实时流量监控和统计
- 🌐 **Web界面**: 友好的管理界面
- 🛡️ **探测抵抗**: 内置探测抵抗功能
- ⚡ **高性能**: 基于 Caddy v2 的高性能代理

## 快速开始

### 编译

```bash
# 克隆仓库
git clone https://github.com/simtelboy/caddysingleFile.git
cd caddysingleFile

# 准备嵌入文件
cd caddy_files
zip -r ../embedded_files.zip .
cd ..

# 使用 xcaddy 编译
CGO_ENABLED=1 xcaddy build --with github.com/caddyserver/forwardproxy=.