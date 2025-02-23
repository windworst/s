# S Scanner

这是一个用 Go 语言重写的 S 端口扫描器，完全复刻了原版 S 扫描器的功能和使用方式。原版 S 扫描器是一个由 Metasploit 团队开发的高效端口扫描工具，以其简洁的输出格式和高效的扫描性能而闻名。

本项目旨在提供一个完全兼容的开源实现，保持了原版扫描器的所有特性：
- 简洁的命令行界面
- 精简的输出格式（仅显示开放端口）
- 高效的扫描性能
- 完全兼容的命令行参数

## 功能特点

- 支持 TCP Connect 扫描和 SYN 扫描
- 支持多种 IP 格式：单个 IP、IP 范围、CIDR
- 支持多种端口格式：单个端口、端口范围、端口列表
- 支持获取服务 Banner
- 支持 HTTP 服务器 Banner 识别
- 支持多线程扫描
- 支持扫描结果保存

## 编译安装

### 使用 Go 命令

```bash
git clone <repository_url>
cd s
go build -o s cmd/scanner/main.go
```

### 使用 Makefile（推荐）

项目提供了 Makefile 来简化构建过程：

```bash
# 构建项目（包含运行测试）
make

# 仅构建项目
make build

# 运行测试
make test

# 更新依赖
make deps

# 清理构建文件
make clean

# 安装到系统
sudo make install

# 从系统中卸载
sudo make uninstall
```

#### 交叉编译

```bash
# 编译 Linux 版本
make build-linux

# 编译 macOS (Intel) 版本
make build-mac

# 编译 macOS (Apple Silicon) 版本
make build-mac-arm64

# 编译 Windows 版本
make build-windows
```

## 使用方法

```bash
s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]
```

### 参数说明

- `TCP/SYN`: 扫描方式（SYN 扫描需要 root/管理员权限）
- `StartIP`: 起始 IP 地址
- `EndIP`: 结束 IP 地址（可选）
- `Ports`: 端口号
- `Threads`: 线程数（可选，默认 512）
- `/T(N)`: 超时时间（可选，默认 3 秒）
- `/Banner`: 获取服务 Banner
- `/HBanner`: 获取 HTTP 服务器 Banner
- `/Save`: 保存扫描结果

### 使用示例

1. TCP 扫描单个 IP 和端口：
```bash
s TCP 192.168.1.1 80
```

2. TCP 扫描 IP 范围：
```bash
s TCP 192.168.1.1 192.168.1.254 80
```

3. TCP 扫描 CIDR：
```bash
s TCP 192.168.1.0/24 80
```

4. 扫描多个端口：
```bash
s TCP 192.168.1.1 80,443,8080
```

5. 扫描端口范围：
```bash
s TCP 192.168.1.1 1-65535
```

6. 获取服务 Banner：
```bash
s TCP 192.168.1.1 80 /BANNER
```

7. SYN 扫描（需要 root 权限）：
```bash
sudo s SYN 192.168.1.1 80
```

## 注意事项

1. SYN 扫描需要 root/管理员权限
2. 扫描结果会保存在 `results` 目录下（使用 `/Save` 选项时）
3. 扫描结果包含 TXT 和 JSON 两种格式

## 与原版的区别

本实现完全复刻了原版 S 扫描器的功能和使用方式，主要区别在于：
1. 使用 Go 语言重写，提供更好的跨平台支持
2. 开源实现，代码结构清晰，易于扩展
3. 增加了 JSON 格式的结果输出
4. 优化了内存使用和并发处理
5. 提供了 Makefile 支持，简化构建和安装过程