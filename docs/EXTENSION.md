# 扩展信息（DHS LAN Web Access）

本文档集中说明本扩展（DSH 插件）的能力、分发方式、配置与安全边界。安装步骤见 [README](../README.md)，详细排障见 [安装与使用说明](安装与使用说明.md)。

## 基本信息

| 项目 | 值 |
|---|---|
| 名称 | 局域网网页访问（LAN Web Access） |
| 包名 | `@local/dsh-lan-access` |
| 版本 | 1.0.0 |
| 类型 | DeepSeek Harness Host 插件（bundle，`dsh.bundle.patch`） |
| 运行环境 | DeepSeek Harness 桌面版（在 0.2.1-rc.3 / Electron 44.7.0 / Windows 验证） |
| 依赖 | 无（仅 Node.js 内置模块：`http`、`https`、`net`、`crypto`、`os`、`fs`、`path`） |
| 许可证 | MIT |
| 源码 | https://github.com/wwb051221/DHS-LAN-Web-Access |
| 发布页 | https://github.com/wwb051221/DHS-LAN-Web-Access/releases |
| 插件索引 | https://wwb051221.github.io/DHS-LAN-Web-Access/market/index.json |

## 能力

| 能力 | 说明 |
|---|---|
| 局域网访问 | 默认监听 `0.0.0.0:8848`，将 HTTP/WebSocket 反向代理到本机 DSH 网页服务 |
| 密码登录 | 其他设备打开端口先看到登录页，密码正确后进入完整网页界面 |
| 自定义密码 | 面板中设置 6–128 位密码，或随机重新生成 |
| 会话吊销 | 改密后旧设备会话立即失效（页面 / API / WebSocket） |
| 防暴力破解 | 登录与改密共用限速：1 分钟内 5 次失败锁定 1 分钟；恒定时间比较 |
| 管理面板 | `/_lan-access`：局域网地址、密码查看/复制、改密、防火墙提示 |

## 工作原理

1. **为什么需要插件**：DSH 内置网页服务只监听 `127.0.0.1`，且 Host/Origin 防护拒绝远程来源，局域网设备无法直接访问。
2. **代理层**：插件另起监听器，转发 HTTP/WebSocket，并将 `Host` / `Origin` / `Referer` 重写为回环地址以通过防护。
3. **认证**：访客密码正确后，插件在**服务端**完成 DSH 启动令牌交换，只把签名会话 Cookie 交给浏览器；启动令牌不暴露给访客，LAN 端口不接受 `?token=`。
4. **会话吊销**：改密时记录会话截止时间，代理层剔除早于该时间的会话 Cookie。

## 分发方式

1. **Release 安装包**：`dsh-lan-access-v1.0.0.zip`，解压后在 DSH「插件 → 添加插件」填绝对路径。
2. **本地目录**：克隆仓库后直接把仓库根目录作为安装目标。
3. **插件索引（推荐）**：在 DSH 中打开「实验性插件 → 自定义插件索引」，进入「发现 → 添加索引源」，添加：
   `https://wwb051221.github.io/DHS-LAN-Web-Access/market/index.json`
   然后搜索「局域网网页访问」安装（索引版本指向仓库 `v1.0.0` 提交）。

## 配置

| 字段 | 默认值 | 说明 |
|---|---|---|
| `host` | `0.0.0.0` | 局域网监听地址 |
| `port` | `8848` | 局域网端口；`0` 表示系统分配 |
| `password` | 无 | 固定密码；设置后优先于自动生成的密码 |

修改方式：编辑 profile 补丁（id 为 `dsh-lan-access`）或让 Agent 修改；改端口需重启程序。

## 密码与会话

- 未配置 `password` 时自动生成 12 位随机密码，保存在 `%USERPROFILE%\.dsh\.dsh-lan-access.json`（或 `$DSH_HOME` 下）。
- 面板中可自定义或随机重置；两种方式都会吊销此前所有设备会话。
- 本机面板（`/_lan-access`）本身也需密码登录，但不受 LAN 会话吊销影响。

## 安全边界

- 局域网内为**明文 HTTP**，会话 Cookie 可能被同一网络窃听；建议只在可信网络使用，或用防火墙限制来源。
- 密码以明文保存在当前用户目录的配置文件中，请勿分享该文件。
- 不提供 TLS；如需公网暴露，应另行部署 HTTPS 反向代理。
- 代理层会重写请求头，但不会绕过 DSH 自身的认证与权限检查。

## 已验证范围

- 密码登录、登录后页面 / `/api` / WebSocket 升级；
- 自定义密码与随机重置、长度与确认校验；
- 改密后旧页面 / API / WebSocket 会话全部失效；
- 异常连接（强制重置、畸形请求、并发、上传中断）下 Host 进程稳定；
- 插件禁用释放端口、启用重新绑定。

**未验证**：真实手机 / 另一台电脑的最终连通性（受防火墙与网络环境影响）；HTTPS/TLS。

## 文件结构

```
dsh-lan-access/
├── package.json              插件清单（bundle 声明）
├── cordis.patch.yml          默认配置（0.0.0.0:8848）
├── index.js                  插件实现（代理 / 登录 / 面板 / 会话吊销）
├── locale/                   中英文显示名与描述
├── icon.svg                  插件图标
├── docs/
│   ├── 安装与使用说明.md      安装、配置、排障
│   ├── EXTENSION.md          本文档
│   ├── GITHUB_USER.md        维护者 GitHub 信息
│   └── market/index.json     插件索引（Discover 用）
├── .github/                  Issue 模板、PR 模板
├── CHANGELOG.md
└── LICENSE
```

## 相关链接

- 仓库：https://github.com/wwb051221/DHS-LAN-Web-Access
- 发布页：https://github.com/wwb051221/DHS-LAN-Web-Access/releases/tag/v1.0.0
- 插件索引：https://wwb051221.github.io/DHS-LAN-Web-Access/market/index.json
- 使用文档：[安装与使用说明.md](安装与使用说明.md)
