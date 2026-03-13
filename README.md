# api-clawer

简易网易云音乐客户端抓包工具, 适用于贡献 NeteaseCloudMusicApi 项目

## 使用方法 (重要)

请参考[这篇文章](https://www.focalors.ltd/post/how-to-contribute-ncm-api)获取详细的使用说明和配置指南。

## 功能

- 抓取并输出网易云音乐客户端的 HTTP 请求和响应数据
- 数据解密并以 JSON 格式输出
- 本地运行两个服务器：抓包服务器和前端显示服务器
- 前端界面实时显示抓包数据

## 安装

```bash
pnpm install
```

## 配置

1. 复制环境变量模板：

```bash
copy .env.example .env
```

2. 编辑 `.env` 文件，设置端口：

```
PORT=3000
HOOK_PORT=9000
```

## 证书生成

HTTPS 代理需要自签名证书。首次运行前需要生成证书：

```bash
cd src/server
node generate-cert.js
```

这将生成 `server.crt` 和 `server.key` 文件。

> **注意**：这是自签名证书，仅用于开发环境。使用时需要在客户端信任此证书。

## 运行

运行以下命令：

```bash
pnpm start
```

## 使用

1. **启动服务器**

   运行 `pnpm start`，将启动两个服务：
   - 前端服务器：`http://localhost:3000`
   - 抓包代理服务器：`http://localhost:9000`

2. **配置网易云音乐客户端**

   - 找到网易云音乐客户端的网络设置
   - 将 HTTP 代理设置为：`http://localhost:9000`
   - 保存设置并重启客户端

3. **查看抓包数据**

   - 打开浏览器访问：`http://localhost:3000`
   - 在网易云音乐客户端中进行操作（如搜索、播放音乐）
   - 抓包数据将实时显示在前端界面

4. **信任证书**（首次使用 HTTPS 时）

   - 如果客户端提示证书错误，需要手动信任 `src/server/server.crt` 证书文件

## 项目结构

```
src/
├── server/          # 抓包服务器
│   ├── app.js       # 服务器入口
│   ├── hook.js      # 数据拦截和解密
│   ├── server.js    # 代理服务器核心
│   ├── server.crt   # HTTPS 证书（运行 generate-cert.js 生成）
│   └── server.key   # HTTPS 私钥（运行 generate-cert.js 生成）
└── client/          # 前端服务器
    ├── app.js       # 前端服务器
    └── public/
        └── index.html # 前端界面
```

## 故障排除

### 代理不工作

1. 检查证书文件是否存在：
   ```bash
   dir src\server\server.crt src\server\server.key
   ```
   如果不存在，运行 `node src/server/generate-cert.js`

2. 确认端口没有被占用：
   ```bash
   netstat -ano | findstr :3000
   netstat -ano | findstr :9000
   ```

3. 检查 `.env` 文件配置是否正确

### 前端页面无法访问

- 确认前端服务器已启动（查看控制台输出）
- 检查端口 3000 是否被占用
- 尝试清除浏览器缓存

### 无法抓取数据

- 确认网易云音乐客户端代理设置正确
- 尝试重启网易云音乐客户端
- 检查抓包服务器日志是否有错误信息

## 环境变量说明

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| PORT | 3000 | 前端服务器端口 |
| HOOK_PORT | 9000 | 抓包代理服务器端口 |
| NETEASE_COOKIE | - | 网易云音乐 Cookie（可选） |
| PROXY_URL | - | 上游代理 URL（可选） |
| FORCE_HOST | - | 强制指定网易云音乐服务器 IP（可选） |
| STRICT | false | 是否启用严格模式（可选） |
| CNRELAY | - | 中继服务器地址（可选） |

详细配置请参考 `.env.example` 文件。
