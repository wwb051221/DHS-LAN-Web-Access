# DHS LAN Web Access

让局域网内的手机、平板和其他电脑，通过浏览器访问本机的 **DeepSeek Harness** 网页界面。

- **密码登录**：像普通网站一样打开、输入密码即可，不再需要复制令牌链接
- **自定义密码**：面板中自定义（6–128 位）或随机重新生成
- **会话吊销**：修改密码后，之前已登录的设备立即失效
- **完整可用**：HTTP 与 WebSocket 反向代理，聊天、设置、文件、终端等界面功能完整
- **零依赖**：仅使用 Node.js 内置模块，无需安装任何 npm 依赖

> 适用于 Windows 上的 DeepSeek Harness 桌面版；其他平台理论可用（使用 Node 内置 `http`/`https`/`net`），尚未验证。

---

## 功能一览

| 能力 | 说明 |
|---|---|
| 局域网访问 | 默认在 `0.0.0.0:8848` 提供 HTTP/WebSocket 反向代理 |
| 密码登录 | 其他设备先看到登录页，密码正确后进入完整网页界面 |
| 自定义密码 | 面板中设置自己的密码，或随机生成 |
| 会话吊销 | 改密后旧会话立即失效（页面、API、WebSocket） |
| 防暴力破解 | 1 分钟内错 5 次锁定 1 分钟；恒定时间密码比对 |
| 本机管理面板 | 列出局域网地址、查看/复制密码、改密、防火墙提示 |

---

## 快速开始

### 1. 获取插件

- 从 [Releases](https://github.com/wwb051221/DHS-LAN-Web-Access/releases) 下载 `dsh-lan-access-v1.0.0.zip`，解压到固定目录（例如 `D:\dsh-plugins\dsh-lan-access`）；
- 或直接克隆本仓库后使用仓库根目录。

### 2. 安装

1. 打开 DeepSeek Harness，进入左侧边栏 **Plugins（插件）**；
2. 点击 **Add plugin（添加插件）**；
3. 填入解压目录的**绝对路径**，例如 `D:\dsh-plugins\dsh-lan-access`；
4. 点击 **Install（安装）**，确认「局域网网页访问」已启用。

安装立即生效，无需重启（未生效时重启一次 DeepSeek Harness）。卸载：插件详情页 → **Remove**。

### 3. 打开管理面板

```
http://127.0.0.1:<DSH网页端口>/_lan-access
```

`<DSH网页端口>` 是当前 DeepSeek Harness 网页界面的端口（每次启动可能变化）。可向 Agent 询问「当前 DSH 网页端口」，或查看环境变量 `DSH_WEB_URL`。

首次运行的密码会自动生成并保存在 `%USERPROFILE%\.dsh\.dsh-lan-access.json`（若设置 `DSH_HOME` 则在其下）。登录面板后可查看并改成自己的密码。

### 4. 其他设备访问

在面板中找到与手机/电脑同一网络的接口地址（通常是 WLAN / 以太网），在其他设备打开：

```
http://<局域网IP>:8848
```

输入密码即可使用。若打不开，请放行防火墙（管理员 PowerShell）：

```powershell
netsh advfirewall firewall add rule name="DSH LAN Access" dir=in action=allow protocol=TCP localport=8848
```

---

## 工作原理

DeepSeek Harness 的内置网页服务只监听 `127.0.0.1`，并用 Host/Origin 防护拒绝远程来源。本插件：

1. 另起监听器（默认 `0.0.0.0:8848`），把 HTTP/WebSocket 流量反向代理到本机网页服务；
2. 转发时将 `Host` / `Origin` / `Referer` 重写为回环地址，通过请求防护；
3. 访客输入正确密码后，**由插件在服务端**完成 DSH 启动令牌交换，只把签名会话 Cookie 交给浏览器（令牌不暴露给访客）；
4. 改密时记录「会话截止时间」，代理层剔除早于该时间的会话 Cookie，实现旧设备下线。

---

## 配置项

| 字段 | 默认值 | 说明 |
|---|---|---|
| `host` | `0.0.0.0` | 局域网监听地址 |
| `port` | `8848` | 局域网端口；`0` 表示系统分配 |
| `password` | 无 | 固定密码；设置后优先于自动生成的密码 |

修改方式：编辑 profile 补丁 `%USERPROFILE%\.dsh\profiles\<profile>\cordis.patch.yml`（id 为 `dsh-lan-access`），或让 Agent 修改；改端口需重启程序。

---

## 安全说明

- 密码以明文保存在当前用户的 `.dsh-lan-access.json`，仅本机用户可读；
- 局域网内为**明文 HTTP**，会话 Cookie 可能被同一网络窃听，请只在可信网络使用，或用防火墙限制来源；
- LAN 端口不接受 `?token=` 链接，访问必须经过密码；
- 改密会吊销旧会话；登录与改密共用 1 分钟 5 次的限速。

---

## 目录结构

```
.
├── package.json              插件清单（bundle 声明）
├── cordis.patch.yml          默认配置
├── index.js                  插件实现（代理 / 登录 / 面板 / 会话吊销）
├── locale/                   中英文显示名与描述
├── icon.svg                  插件图标
├── docs/安装与使用说明.md      详细使用与排障文档
├── .github/workflows/        CI：语法与清单校验
├── CHANGELOG.md
└── LICENSE
```

---

## 开发与验证

- 运行时：Node.js 内置模块（`http`、`https`、`net`、`crypto`、`os`、`fs`）；
- 本地校验：`node --check index.js`，并确保 `package.json` 的 `dsh.bundle.patch` 指向存在的补丁；
- 本地已验证：密码登录、认证后页面/API/WebSocket、改密吊销、异常连接压力测试、插件启停端口释放。

详细安装、配置、排障见 [docs/安装与使用说明.md](docs/安装与使用说明.md)。

---

## English

**DHS LAN Web Access** exposes the local DeepSeek Harness web GUI to other devices on the same LAN through a password-protected HTTP/WebSocket reverse proxy. It rewrites Host/Origin headers to pass the loopback-only request fence, performs the launch-token exchange server-side so the token never reaches visitors, and revokes old sessions whenever the password changes.

Install: unzip a release and point **Plugins → Add plugin** at the extracted folder's absolute path. Open `http://127.0.0.1:<gui-port>/_lan-access` on the host to get the LAN URL and manage the password.

---

## License

[MIT](LICENSE) © 2026 wwb051221
