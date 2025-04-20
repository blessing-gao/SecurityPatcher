# SecurityPatcher

一键自动修复OpenSSH/OpenSSL安全漏洞的工具，支持多个Linux发行版。

## 项目简介

SecurityPatcher是一个专注于修复服务器关键安全漏洞的开源工具集，当前主要针对OpenSSH和OpenSSL的常见高危漏洞提供一键修复方案。该工具适用于各类Linux服务器，能够自动检测、备份、升级并验证安装结果，为系统管理员提供便捷的安全修复体验。

## 修复的漏洞

本工具能够修复以下高危漏洞：

- **CVE-2023-38408**: OpenSSH代理转发远程代码执行漏洞
- **CVE-2023-28531**: OpenSSH智能卡密钥添加漏洞
- **CVE-2023-51767**: OpenSSH身份验证绕过漏洞
- **CVE-2023-51384**: OpenSSH PKCS11目标约束漏洞
- **CVE-2023-48795**: OpenSSH Terrapin前缀截断攻击漏洞
- **CVE-2023-51385**: OpenSSH命令注入漏洞

## 主要功能

- **自动检测**: 识别当前系统的OpenSSH和OpenSSL版本
- **多源下载**: 支持从多个镜像源下载源码
- **备份保护**: 自动备份原有配置
- **安全加固**: 应用安全最佳实践配置
- **故障保护**: 使用telnet作为备用登录方式
- **自动验证**: 升级后自动测试服务是否正常
- **版本可选**: 通过命令行参数指定需要的版本

## 使用方法

### 基本用法

```bash
# 使用默认版本(OpenSSH 9.9p1)
sudo ./security-patcher.sh

# 指定版本
sudo ./security-patcher.sh 9.9p1 3.4.1
```

### 命令行参数

```
使用方法: ./security-patcher.sh [openssh版本] [openssl版本]

参数:
  openssh版本    要安装的OpenSSH版本，例如9.9p1
  openssl版本    要安装的OpenSSL版本，例如3.4.1

示例:
  ./security-patcher.sh 9.9p1 3.4.1    安装OpenSSH 9.9p1和OpenSSL 3.4.1
  ./security-patcher.sh 9.9p1          只安装OpenSSH 9.9p1
  ./security-patcher.sh                使用默认版本(OpenSSH 9.9p1)
```

## 安装要求

- 支持apt包管理器的Linux发行版(Ubuntu/Debian等)
- root权限
- 基本开发工具(build-essential)
- 互联网连接(用于下载源码)

## 注意事项

1. **备份**: 脚本会自动备份重要配置文件，备份路径将在执行时显示
2. **安全性**: 脚本会临时启用telnet服务作为备用登录方式，升级完成后建议禁用
3. **重启**: 如果升级了OpenSSL，建议重启系统以确保所有更改生效

## 贡献指南

欢迎提交问题报告、功能请求和贡献代码。请遵循以下步骤：

1. Fork本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

本项目采用MIT许可证 - 详情请查看 [LICENSE](LICENSE) 文件

## 致谢

- OpenSSH和OpenSSL开发团队
- 所有为安全漏洞研究和披露做出贡献的安全研究人员

## 免责声明

本工具仅供学习和系统维护使用。使用前请充分测试并了解其影响。作者不对因使用本工具导致的任何损失负责。
