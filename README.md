# SSHPortForward (SSH隧道管理器)

一个基于Python开发的SSH反向隧道管理工具，提供图形界面，支持多配置管理、自动重连、系统托盘运行等功能，方便用户管理多个SSH隧道连接。

## 功能特点

- 图形化界面，操作简单直观
- 支持 SSH 反向隧道连接
- 多配置管理，可保存多个连接配置
- 自动重连机制
- 系统托盘支持
- 连接历史记录
- 配置导入/导出
- 密码加密存储
- 详细的运行日志

## 安装说明

### 直接运行可执行文件
1. 从 Release 页面下载最新版本的可执行文件
2. 双击运行 `SSH隧道管理器.exe`

### 从源码运行
1. 确保已安装 Python 3.8 或更高版本
2. 安装依赖：

```bash
pip install -r requirements.txt
```
3. 运行程序：

```bash
python src/main.py
```

## 使用说明

### 基本配置
- SSH主机：远程 SSH 服务器的地址
- SSH用户：SSH 登录用户名
- SSH密码：SSH 登录密码
- 本地端口：在 SSH 服务器上监听的端口
- 远程主机：需要转发到的目标主机地址
- 远程端口：需要转发到的目标主机端口

### 配置管理
- 保存配置：保存当前的连接参数
- 导入配置：从文件导入配置
- 导出配置：将配置导出到文件
- 删除配置：删除选中的配置

### 系统托盘
- 双击托盘图标：显示/隐藏主窗口
- 右键托盘图标：显示快捷菜单
- 支持后台运行

## 项目结构

```
SSHPortForward/
├── src/                      # 源代码目录
│   └── main.py               # 主程序
├── data/                     # 配置文件和数据存储目录
│   ├── config.json           # 保存的连接配置
│   ├── history.json          # 连接历史记录
│   ├── settings.json         # 程序设置
│   ├── icon.ico              # 程序图标
│   └── encryption.key        # 密码加密密钥
├── logs/                     # 运行日志目录
│   └── SSHPortForward.log    # 运行日志
├── requirements.txt          # 依赖库列表
├── README.md                 # 项目说明
└── LICENSE                   # 许可证
```

## 开发说明

### 环境要求
- Python 3.8+
- PyQt5
- paramiko
- cryptography

## 开源协议

本项目采用 MIT 许可证。详细内容请查看 [LICENSE](LICENSE) 文件。