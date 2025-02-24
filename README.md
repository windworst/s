# S Scanner

这是一个用 Go 语言重写的 S 端口扫描器，完全复刻了原版 S 扫描器的功能和使用方式。原版 S 扫描器是由WinEggDrop开发的高效端口扫描工具，以其简洁的输出格式和高效的扫描性能而闻名。

本项目旨在提供一个完全兼容的开源实现，保持了原版扫描器的所有特性：
- 简洁的命令行界面
- 精简的输出格式（仅显示开放端口）
- 高效的扫描性能
- 完全兼容的命令行参数

## 功能特点

- 支持 TCP 连接扫描和 SYN 扫描
- 多线程并发扫描
- 支持 IP 范围扫描
- 支持多种端口格式：单个端口、端口范围、端口列表
- 可选获取服务 Banner 信息
- 支持 HTTP 服务的 Server 头信息获取
- 可将结果保存到文件

## 使用方法

### 编译

```bash
# 编译当前平台
make build

# 交叉编译
make build-linux    # Linux平台
make build-mac      # macOS平台
make build-windows  # Windows平台
```

### 命令格式

```
s TCP/SYN StartIP [EndIP] Ports [Threads] [/T(N)] [/(H)Banner] [/Save]
```

参数说明：
- `TCP/SYN`: 扫描模式
- `StartIP`: 起始IP地址
- `EndIP`: 结束IP地址（可选）
- `Ports`: 端口列表
- `Threads`: 线程数（默认256）
- `/T(N)`: 超时时间（秒）
- `/Banner`: 获取服务Banner
- `/HBanner`: 获取HTTP服务Banner
- `/Save`: 保存结果到文件

### 使用示例

```bash
# TCP扫描单个IP的80端口
s TCP 12.12.12.12 80 512

# TCP扫描IP范围的多个端口
s TCP 12.12.12.12 12.12.12.254 80,443,8080 512

# TCP扫描带Banner获取
s TCP 12.12.12.12 12.12.12.254 80 512 /Banner

# TCP扫描带HTTP Banner获取
s TCP 12.12.12.12 12.12.12.254 80 512 /HBanner

# SYN扫描（需要root/管理员权限）
s SYN 12.12.12.12 12.12.12.254 80

# 扫描端口范围
s TCP 12.12.12.12 1-65535 512

# 指定超时和保存结果
s TCP 12.12.12.12 80 512 /T8 /Save

# 使用CIDR格式扫描网段
s TCP 12.12.12.12/24 80 512
```

### 输出格式

```
TCP Port Scanner V1.2 By WinEggDrop

Normal Scan: About To Scan 12.12.12.12 Using 512 Threads
12.12.12.12     80    Open
12.12.12.12     443   Open
1000 Ports Scanned.
```

带Banner的输出：
```
12.12.12.12     80    -> "nginx/1.18.0"
12.12.12.12     443   -> "Apache/2.4.41"
```

## 注意事项

1. SYN 扫描需要 root/管理员权限
2. Windows 系统目前仅支持 TCP 扫描模式
3. 扫描结果默认保存在当前目录的 Result.txt 文件中
4. 建议根据网络状况调整线程数和超时时间

## 构建要求

- Go 1.16 或更高版本
- 支持的操作系统：Linux、macOS、Windows

## 许可证

MIT License