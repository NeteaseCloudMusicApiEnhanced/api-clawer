# AGENTS.md

## Setup

```bash
pnpm install
cp .env.example .env
node src/server/generate-cert.js  # Generate HTTPS certs for proxy
```

## Run

```bash
pnpm start
```

- Frontend: http://localhost:3000
- Proxy server: http://localhost:9000

## Test

Jest tests exist in `src/server/request.test.js`. No test script in package.json - run with:
```bash
npx jest
```

## Project Structure

- `src/index.js` - Main entry, starts both servers
- `src/server/` - Proxy server (app.js, server.js, hook.js)
- `src/client/` - Frontend static files

## Important Notes

- Requires pnpm (specified in `packageManager` field)
- HTTPS proxy needs `server.crt`/`server.key` generated via `generate-cert.js`
- First-time: must trust the self-signed cert in Netease Music client

## xeapi 抓包 (MITM 换公钥)

xeapi 的请求体用「服务器 X25519 公钥」保护, 拿不到服务器私钥, 所以必须做一次 MITM:
拦截客户端拉公钥的响应, 把公钥换成我们自己的, 客户端就会把动态密钥加密给我们。

- 拉公钥的路径**只有两个**:
  `/api/bsr/sk/get` 与 `/api/gorilla/anti/crawler/security/key/get`
- 请求体有两代格式, **与平台无关**, 两边都可能出现:
  - `CSR`(新): 字段 `C`(base64url), Mid Transform 轮转原始字节
  - `BSR`(老): 字段 `B`(base64),   Mid Transform 轮转 base64 文本
- 静态密钥分平台 (PC / 移动端各一把), 平台由「哪把静态密钥解得开」决定, **不能靠格式或路径判断**;
  换公钥回去时也必须用回原来那把静态密钥, 否则客户端解不开
- 转发上游时只用真实公钥把 `S` 重新封装, `B/C`、`R`、动态密钥、`os`、`sk` 全部原样透传
- **动态密钥有两种长度, 外层 AES 要按长度自动选**: 客户端自己随机生成的是 **16 字节**
  (AES-128); 服务器在响应头 `x-encr-sskey` 下发会话密钥后, 客户端直接把它当 **32 字节**
  AES-256 密钥用。写死 AES-128 会在会话模式下抛 `Invalid key length`, 表现为「开头几条能解开,
  之后全部解不开」——这正是移动端 MITM 曾经"失效"的真实原因 (换包其实一直是成功的,
  App 会把我们的公钥持久化到 `files/aegissdk/`)。实现见 `decryptEcbAuto`
- 响应不用改包: `AES-128-ECB(eapiKey)` 解密即可 (明文可能是 gzip)
- 若某请求解不开 (客户端在代理启动前就拿到了真实公钥), 该请求原样转发, 不破坏链路;
  重启客户端即可让它重新走一次 MITM 握手
- **客户端常常按 IP 直连**: App 用 HTTPDNS (`httpdns.music.163.com`) 自己解析,
  拿到的 CDN IP 与本机 DNS 完全不同, CONNECT 目标就是 IP。所以 MITM 与否不能只看域名/本机 IP,
  必须看 TLS 的 **SNI**: `hook.negotiate.before` 发现 SNI 是抓包名单里的域名时,
  会断开直连、把连接改接到本地 MITM 端口 (客户端首包还没发出去, 完全无感)。
  注意 TLS 1.3 + 后量子套件 (X25519MLKEM768) 的 ClientHello 可超过一个 TCP 段,
  `server.js` 的 dock 会攒够一整条 TLS 记录再解析 SNI
- 换包只在「拉公钥请求经过代理」时才会发生, 排查时看这几条 info 日志:
  `xeapi: 客户端按 IP 连接, 依据 SNI 改接本地 MITM` (按 IP 连的已被纠正)、
  `xeapi: 收到拉公钥请求` (握手进了代理) / `未走 MITM (透明透传)` (域名不在名单里);
  两条都没有 → 客户端的握手压根没经过本代理 (例如原生网络栈绕过了系统代理)

相关实现: `src/server/xeapi.js` (MITM 编排) + `src/server/crypto.js` (协议原语)

