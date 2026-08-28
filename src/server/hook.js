const parse = require('url').parse;
const crypto = require('./crypto');
const request = require('./request');
const querystring = require('querystring');
const { isHost, cookieToMap, mapToCookie } = require('./utilities');
const { logScope } = require('./logger');
const axios = require('axios');
require('dotenv').config();

// X25519 key pair for xeapi MITM attack (replaces server's public key)
let mitmKeyPair = null;
// 真实服务端公钥 (从 key/get 响应中保存, 用于转发时重加密 S 字段)
let serverPublicKey = null;

const logger = logScope('hook');

// 初始化 MITM 密钥对 (必须在 logger 之后)
try {
	mitmKeyPair = crypto.xeapi.generateMitmKeyPair();
	logger.info({ publicKey: mitmKeyPair.publicKey }, 'MITM X25519 keypair generated');
} catch (e) {
	logger.error('Failed to generate MITM keypair:', e.message);
}

const hook = {
	request: {
		before: () => {},
		after: () => {},
	},
	connect: {
		before: () => {},
	},
	negotiate: {
		before: () => {},
	},
	target: {
		host: new Set(),
		path: new Set(),
	},
};

hook.target.host = new Set([
	'music.163.com',
	'interface.music.163.com',
	'interface3.music.163.com',
	'interfacepc.music.163.com',
	'apm.music.163.com',
	'apm3.music.163.com',
	'interface.music.163.com.163jiasu.com',
	'interface3.music.163.com.163jiasu.com',
]);

hook.target.path = new Set([
	'/api/v3/playlist/detail',
	'/api/v3/song/detail',
	'/api/v6/playlist/detail',
	'/api/album/play',
	'/api/artist/privilege',
	'/api/album/privilege',
	'/api/v1/artist',
	'/api/v1/artist/songs',
	'/api/v2/artist/songs',
	'/api/artist/top/song',
	'/api/v1/album',
	'/api/album/v3/detail',
	'/api/playlist/privilege',
	'/api/song/enhance/player/url',
	'/api/song/enhance/player/url/v1',
	'/api/song/enhance/download/url',
	'/api/song/enhance/download/url/v1',
	'/api/song/enhance/privilege',
	'/api/ad',
	'/batch',
	'/api/batch',
	'/api/listen/together/privilege/get',
	'/api/playmode/intelligence/list',
	'/api/v1/search/get',
	'/api/v1/search/song/get',
	'/api/search/complex/get',
	'/api/search/complex/page',
	'/api/search/pc/complex/get',
	'/api/search/pc/complex/page',
	'/api/search/song/list/page',
	'/api/search/song/page',
	'/api/cloudsearch/pc',
	'/api/v1/playlist/manipulate/tracks',
	'/api/song/like',
	'/api/v1/play/record',
	'/api/playlist/v4/detail',
	'/api/v1/radio/get',
	'/api/v1/discovery/recommend/songs',
	'/api/usertool/sound/mobile/promote',
	'/api/usertool/sound/mobile/theme',
	'/api/usertool/sound/mobile/animationList',
	'/api/usertool/sound/mobile/all',
	'/api/usertool/sound/mobile/detail',
	'/api/vipauth/app/auth/query',
	'/api/music-vip-membership/client/vip/info',
]);

const domainList = [
	'music.163.com',
	'music.126.net',
	'iplay.163.com',
	'look.163.com',
	'y.163.com',
	'interface.music.163.com',
	'interface3.music.163.com',
	'interfacepc.music.163.com',
];

/**
 * 判断是否为网易云相关域名
 */
function isNeteaseHost(hostname) {
	if (!hostname) return false;
	const neteasePatterns = [
		'music.163.com', 'music.126.net', 'vod.126.net',
		'iplay.163.com', 'look.163.com', 'y.163.com',
		'interface.music.163.com', '163yun.com',
		'163jiasu.com', 'netease.com',
	];
	return neteasePatterns.some(p => hostname.includes(p));
}

/**
 * 是否启用完整抓包模式 (非网易云流量也捕获)
 */
function isFullCapture() {
	return global.fullCapture === true;
}

hook.request.before = (ctx) => {
	const { req } = ctx;
	// 记录请求开始时间和请求头
	ctx.startTime = Date.now();
	ctx.requestHeaders = { ...req.headers };
	// 标记是否网易云
	ctx.isNeteaseDomain = isNeteaseHost(req.headers.host);
	
	req.url =
		(req.url.startsWith('http://')
			? ''
			: (req.socket.encrypted ? 'https:' : 'http:') +
				'//' +
				(domainList.some((domain) =>
					(req.headers.host || '').includes(domain)
				)
					? req.headers.host
					: null)) + req.url;
	const url = parse(req.url);
	// 所有请求都走代理 (不再局限网易云)
	ctx.decision = 'proxy';

	if (process.env.NETEASE_COOKIE && url.path.includes('url')) {
		var cookies = cookieToMap(req.headers.cookie);
		var new_cookies = cookieToMap(process.env.NETEASE_COOKIE);

		Object.entries(new_cookies).forEach(([key, value]) => {
			cookies[key] = value;
		});

		req.headers.cookie = mapToCookie(cookies);
		logger.debug('Replace netease cookie');
	}

	if (
		[url.hostname, req.headers.host].some((host) =>
			hook.target.host.has(host)
		) &&
		(url.path.startsWith('/eapi/') || // eapi
			url.path.includes('/xeapi/') || // xeapi (可能带 /store/ 前缀)
			url.path.startsWith('/api/linux/forward')) && // linuxapi
		(req.method === 'POST' || url.path.includes('/xeapi/')) // POST 全支持; xeapi 也可能 GET
	) {
		return request
			.read(req)
			.then((body) => (req.body = body))
			.then((body) => {
				if ('x-napm-retry' in req.headers)
					delete req.headers['x-napm-retry'];
				req.headers['X-Real-IP'] = '118.88.88.88';
				if ('x-aeapi' in req.headers) req.headers['x-aeapi'] = 'false';
				if (
					req.url.includes('stream') ||
					req.url.includes('/eapi/cloud/upload/check')
				)
					return; // look living/cloudupload eapi can not be decrypted
				if (req.headers['Accept-Encoding'])
					req.headers['Accept-Encoding'] = 'gzip, deflate'; // https://blog.csdn.net/u013022222/article/details/51707352
if (body || (req.method === 'GET' && url.path.includes('/xeapi/'))) {
				const netease = {};
				netease.pad = ((body || '').match(/%0+$/) || [''])[0];
					if (url.path === '/api/linux/forward') {
						netease.crypto = 'linuxapi';
					} else if (url.path.includes('/eapi/')) {
						netease.crypto = 'eapi';
					} else if (url.path.includes('/xeapi/')) {
						netease.crypto = 'xeapi';
					} else if (url.path.startsWith('/api/')) {
						netease.crypto = 'api';
					}
					let data;
					switch (netease.crypto) {
						case 'linuxapi':
							data = JSON.parse(
								crypto.linuxapi
									.decrypt(
										Buffer.from(
											body.slice(
												8,
												body.length - netease.pad.length
											),
											'hex'
										)
								)
								.toString()
						);
						netease.path = parse(data.url).path;
						netease.param = data.params;
						break;
						case 'eapi':
							data = crypto.eapi
								.decrypt(
									Buffer.from(
										body.slice(
											7,
											body.length - netease.pad.length
										),
										'hex'
									)
							)
							.toString()
								.split('-36cd479b6b5-');
						netease.path = data[0];
						netease.param = JSON.parse(data[1]);
						if (
							netease.param.hasOwnProperty('e_r') &&
							(netease.param.e_r == 'true' ||
								netease.param.e_r == true)
						) {
							// eapi's e_r is true, needs to be encrypted
							netease.e_r = true;
						} else {
							netease.e_r = false;
						}
						break;
case 'xeapi':
						// xeapi 请求: B/S/R 可能在 body (POST) 或 URL query (GET)
						let bField, sField;
						let queryParams = null;
						
						if (req.method === 'GET' && url.query) {
							// GET 请求: B/S/R 在 URL query 里
							const sp = new URLSearchParams(url.query);
							bField = sp.get('B');
							sField = sp.get('S');
							queryParams = sp;
						} else {
							// POST 请求: B/S/R 在 body 里
							const parsedBody = querystring.parse(body);
							bField = parsedBody.B;
							sField = parsedBody.S;
						}
						
						if (!bField) {
							throw new Error('xeapi request missing B field');
						}
						
						// 尝试解析 xeapi 请求
						let decryptedText = null;
						
						// 方法1: 如果有 MITM 私钥，尝试完整解密 (X25519 + 双层 AES)
						if (mitmKeyPair && sField) {
							try {
								decryptedText = crypto.xeapi.decryptRequest({
									B: bField,
									S: sField,
									privateKey: mitmKeyPair.privateKey,
								});
							} catch(e) {
								logger.warn('xeapi MITM decrypt failed (expected if no MITM):', e.message);
							}
						}
						
						// 方法2: 尝试直接 AES-128-ECB 解密 B 字段 (旧格式兼容)
						if (!decryptedText) {
							try {
								const bodyBuf = Buffer.from(bField, 'base64');
								decryptedText = crypto.xeapi
									.decrypt(bodyBuf)
									.toString();
							} catch(e) {
								// 忽略，降级
							}
						}
						
						// 方法3: URL decode + base64
						if (!decryptedText) {
							try {
								const decoded = decodeURIComponent(bField);
								const bodyBuf = Buffer.from(decoded, 'base64');
								decryptedText = crypto.xeapi
									.decrypt(bodyBuf)
									.toString();
							} catch(e) {
								// 忽略，降级
							}
						}
						
						if (decryptedText) {
							// 新格式: 纯 JSON {queryString, body, method} (buildXeapiPlaintext)
							const xeapiPlain = crypto.xeapi.parseXeapiPlaintext(decryptedText);
							if (xeapiPlain) {
								netease.path = (url.pathname || url.path)
									.replace(/^\/xeapi\//, '/api/')
									.replace(/\/store\/xeapi\//, '/api/');
								const params = {};
								// body 字段 (base64 编码的 urlencoded 参数)
								if (xeapiPlain.body) {
									try {
										const bodyStr = Buffer.from(xeapiPlain.body, 'base64').toString();
										new URLSearchParams(bodyStr).forEach((v, k) => {
											try { params[k] = JSON.parse(v); } catch { params[k] = v; }
										});
									} catch(e) {
										logger.warn('xeapi parse body failed:', e.message);
									}
								}
								// queryString 字段 (URL query 参数, 含 e_r=true)
								if (xeapiPlain.queryString) {
									try {
										new URLSearchParams(xeapiPlain.queryString).forEach((v, k) => {
											if (k === 'e_r') { params.e_r = v; return; }
											try { params[k] = JSON.parse(v); } catch { params[k] = v; }
										});
									} catch(e) {
										logger.warn('xeapi parse queryString failed:', e.message);
									}
								}
								netease.param = params;
								netease.e_r = xeapiPlain.queryString.includes('e_r=true') || params.e_r === 'true' || params.e_r === true;
								netease.method = xeapiPlain.method;
							} else {
								// 旧格式: path-36cd479b6b5-json
								data = decryptedText.split('-36cd479b6b5-');
								netease.path = data[0];
								netease.param = JSON.parse(data[1]);
								if (
									netease.param.hasOwnProperty('e_r') &&
									(netease.param.e_r == 'true' ||
										netease.param.e_r == true)
								) {
									// eapi's e_r is true, needs to be encrypted
									netease.e_r = true;
								} else {
									netease.e_r = false;
								}
							}
						} else {
							// 无法解密 xeapi，但 URL 上的 query 参数就是请求参数喵！
							netease.path = url.pathname;
							const queryParamsObj = {};
							if (url.query) {
								const searchParams = new URLSearchParams(url.query);
								for (const [key, value] of searchParams) {
									try {
										// 尝试 JSON 解析 (大部分值都是 JSON 字符串)
										queryParamsObj[key] = JSON.parse(decodeURIComponent(value));
									} catch {
										// 不是 JSON 就用原始值
										queryParamsObj[key] = decodeURIComponent(value);
									}
								}
							}
							netease.param = queryParamsObj;
						}
					break;
						case 'api':
							data = {};
							decodeURIComponent(body)
								.split('&')
								.forEach((pair) => {
									let [key, value] = pair.split('=');
									data[key] = value;
								});
						netease.path = url.path;
						netease.param = data;
						break;
						default:
							// unsupported crypto
							break;
					}
					netease.path = netease.path.replace(/\/\d*$/, '');
					// Save original URL path for toggle display and normalize prefixes
					if (netease.crypto === 'eapi') {
						netease.rawPath = url.pathname || url.path;
					} else if (netease.crypto === 'xeapi') {
						netease.rawPath = url.pathname || url.path;
						if (netease.path.startsWith('/xeapi/')) {
							netease.path = netease.path.replace(/^\/xeapi\//, '/api/');
						} else if (netease.path.startsWith('/store/xeapi/')) {
							netease.path = netease.path.replace(/^\/store\/xeapi\//, '/api/');
						}
						// ===== MITM 中继: 用真实服务端公钥重加密 S 字段 =====
						// 客户端用 MITM 公钥加密 S → 真实服务器解不了
						// 代理用 MITM 私钥解出 dynamicKey → 用真实服务端公钥重新加密 S → 转发
						if (mitmKeyPair && serverPublicKey && sField) {
							try {
								const newS = crypto.xeapi.reEncryptXeapiS(
									sField,
									serverPublicKey,
									mitmKeyPair.privateKey
								);
								if (req.method === 'GET') {
									// GET: 替换 URL query 中的 S 参数
									const sp = new URLSearchParams(url.query);
									sp.set('S', newS);
									const newQuery = sp.toString();
									req.url = `${url.pathname}?${newQuery}`;
									netease.relayed = true;
								} else {
									// POST: 替换 body 中的 S 参数
									const newBody = body.replace(
										/([?&]S=)[^&]*(&|$)/,
										`$1${encodeURIComponent(newS)}$2`
									);
									req.body = newBody;
									req.headers['content-length'] = Buffer.byteLength(newBody);
									netease.relayed = true;
								}
								logger.info(
									{ path: netease.path },
									'xeapi MITM relay: S field re-encrypted with server public key'
								);
							} catch(e) {
								logger.warn('xeapi MITM relay failed:', e.message);
							}
						}
					}
					ctx.netease = netease;
					logger.info({ path: netease.path, params: netease.param }, 'Captured request')
				}
			})
			.catch(
				(error) =>
					error &&
					logger.error(
						error,
						`A error occurred in hook.request.before when hooking ${req.url}.`
					)
			);
	} else if (
		hook.target.host.has(url.hostname) &&
		(url.path.startsWith('/weapi/') || url.path.startsWith('/api/'))
	) {
		req.headers['X-Real-IP'] = '118.88.88.88';
		const weapiUrlPath = url.path;
		ctx.netease = {
			crypto: url.path.startsWith('/weapi/') ? 'weapi' : 'api',
			web: true,
			rawPath: url.path.startsWith('/weapi/') ? weapiUrlPath : undefined,
			path: weapiUrlPath
				.replace(/^\/weapi\//, '/api/')
				.split('?')
				.shift() // remove the query parameters
				.replace(/\/\d*$/, ''),
		};
	} else if (req.url.includes('package')) {
		try {
			const data = req.url.split('package/').pop().split('/');
			const url = parse(crypto.base64.decode(data[0]));
			const id = data[1].replace(/\.\w+/, '');
			req.url = url.href;
			req.headers['host'] = url.hostname;
			req.headers['cookie'] = null;
			ctx.package = { id };
			ctx.decision = 'proxy';
		} catch (error) {
			ctx.error = error;
			ctx.decision = 'close';
		}
	}
};

hook.request.after = (ctx) => {
	const { req, proxyRes, netease, package: pkg } = ctx;

	if (netease) {
		// 计算请求耗时
		const duration = ctx.startTime ? Date.now() - ctx.startTime : 0;
		// 捕获响应头
		const responseHeaders = proxyRes ? { ...proxyRes.headers } : {};
		delete responseHeaders['transfer-encoding'];
		
		return request
			.read(proxyRes, true)
			.then((buffer) => {
				if (!buffer.length) return Promise.reject();
				proxyRes.body = buffer;
				// 🔧 移除 Content-Encoding 头，因为响应体已经被解压
				delete proxyRes.headers['content-encoding'];
				return buffer; // 继续传递 buffer
			})
			.then((buffer) => {
				const patch = (string) =>
					string.replace(
						/([^\\]"\s*:\s*)(\d{16,})(\s*[}|,])/g,
						'$1"$2L"$3'
					); // for js precision

				// ===== xeapi key/get 拦截: 替换公钥为 MITM 公钥 =====
				// 客户端通过 POST /api/gorilla/anti/crawler/security/key/get 获取 xeapi 公钥
				// 代理把响应里的公钥换成自己的 X25519 公钥, 这样客户端会用 MITM 公钥加密 S 字段
				if (
					netease.path &&
					netease.path.includes('gorilla/anti/crawler/security/key/get')
				) {
					try {
						const jsonBody = JSON.parse(buffer.toString());
						const encData =
							jsonBody.data && jsonBody.data.encryptedData;
						if (encData && mitmKeyPair) {
							// 用 xeapiStaticKey 解密 encryptedData (AES-256-ECB)
							const decrypted = crypto.xeapi.decryptResponse(
								Buffer.from(encData, 'base64')
							);
							const keyInfo = JSON.parse(decrypted.toString());
							// 保存真实服务端公钥 (用于转发时重加密 S 字段)
							if (keyInfo.publicKey) {
								serverPublicKey = keyInfo.publicKey;
							}
							// 替换为 MITM 公钥
							const oldKey = keyInfo.publicKey;
							keyInfo.publicKey = mitmKeyPair.publicKey;
							// 重新加密 encryptedData
							const newEnc = crypto.xeapi.encryptResponse(
								Buffer.from(JSON.stringify(keyInfo))
							);
							jsonBody.data.encryptedData = newEnc.toString('base64');
							// 更新转发给客户端的响应体
							proxyRes.body = Buffer.from(JSON.stringify(jsonBody));
							delete proxyRes.headers['content-length'];
							netease.jsonBody = jsonBody;
							logger.info(
								{
									oldKey: (oldKey || '').slice(0, 16) + '...',
									newKey: mitmKeyPair.publicKey.slice(0, 16) + '...',
								},
								'xeapi key/get response patched (MITM public key injected)'
							);
						}
					} catch (e) {
						logger.error('key/get patch failed:', e.message);
					}
				}

				if (netease.e_r) {
					// 已知加密: 用 eapiKey 解密 (xeapi/eapi 响应都用 eapiKey)
					// eapiResDecrypt 处理 AES-128-ECB + gzip 魔头检查
					try {
						netease.jsonBody = crypto.eapiResDecrypt(buffer);
					} catch(e) {
						// 解密失败则尝试直接 JSON.parse (可能是明文)
						netease.jsonBody = JSON.parse(patch(buffer.toString()));
					}
				} else {
					// 未知是否加密: 先尝试直接解析 JSON
					try {
						netease.jsonBody = JSON.parse(patch(buffer.toString()));
					} catch(e) {
						// 不是 JSON? 可能是加密的，尝试 eapi 解密 (xeapi 不解密请求参数时 e_r 未设)
						try {
							netease.jsonBody = crypto.eapiResDecrypt(buffer);
							netease.e_r = true; // 标记为已加密
						} catch(e2) {
							// 真的不是 JSON 也不是加密，重新抛原始错误
							throw e;
						}
					}
				}

				// Send data to frontend for all captured requests
				const dataToSend = {
					timestamp: new Date().toISOString(),
					path: netease.path,
					rawPath: netease.rawPath || undefined,
					crypto: netease.crypto || null,
					param: netease.param,
					response: netease.jsonBody,
					statusCode: proxyRes.statusCode,
					method: req.method,
					duration,
					requestHeaders: ctx.requestHeaders,
					responseHeaders,
					isNetease: true,
				};
				axios.post(`http://localhost:${process.env.PORT || 3000}/api/capture`, dataToSend)
					.catch(err => logger.error('Failed to send data to frontend:', err));
			})
			.catch((error) => {
				// 即使读取响应体失败，也发送基本信息到前端
				const dataToSend = {
					timestamp: new Date().toISOString(),
					path: netease.path,
					rawPath: netease.rawPath || undefined,
					crypto: netease.crypto || null,
					param: netease.param,
					response: null,
					statusCode: proxyRes ? proxyRes.statusCode : null,
					error: error.message,
					method: req.method,
					duration,
					requestHeaders: ctx.requestHeaders,
					responseHeaders,
					isNetease: true,
				};
				axios.post(`http://localhost:${process.env.PORT || 3000}/api/capture`, dataToSend)
					.catch(err => logger.error('Failed to send data to frontend:', err));
				
				if (error) {
					logger.error(
						error,
						`A error occurred in hook.request.after when hooking ${req.url}.`
					);
				}
			});
	} else if (pkg) {
		if (new Set([201, 301, 302, 303, 307, 308]).has(proxyRes.statusCode)) {
			return request(
				req.method,
				parse(req.url).resolve(proxyRes.headers.location),
				req.headers
			).then((response) => (ctx.proxyRes = response));
		} else if (/p\d+c*\.music\.126\.net/.test(req.url)) {
			proxyRes.headers['content-type'] = 'audio/*';
		}
	}

	// ========== 通用抓包: 捕获所有请求 (非网易云也抓) ==========
	// 只在全抓包模式或网易云域名下捕获
	if (!netease && !pkg && (isFullCapture() || ctx.isNeteaseDomain)) {
		const duration = ctx.startTime ? Date.now() - ctx.startTime : 0;
		const responseHeaders = proxyRes ? { ...proxyRes.headers } : {};
		delete responseHeaders['transfer-encoding'];
		const reqUrl = req.url || '';
		const contentType = (proxyRes && proxyRes.headers['content-type']) || '';

		// 基本数据 (所有请求都有)
		const dataToSend = {
			timestamp: new Date().toISOString(),
			path: reqUrl,
			method: req.method || 'GET',
			statusCode: proxyRes ? proxyRes.statusCode : null,
			duration,
			requestHeaders: ctx.requestHeaders,
			responseHeaders,
			isNetease: ctx.isNeteaseDomain || false,
			hostname: parse(reqUrl).hostname || req.headers.host || '',
		};

		// 尝试读取响应体 (仅对文本类响应，且大小限制 512KB)
		const isTextResponse = contentType.includes('json') || contentType.includes('text') || contentType.includes('javascript') || contentType.includes('xml');
		const contentLength = parseInt(proxyRes && proxyRes.headers['content-length'] || '0', 10);

		if (proxyRes && isTextResponse && contentLength < 512 * 1024) {
			return request.read(proxyRes, true)
				.then((buffer) => {
					if (buffer && buffer.length > 0 && buffer.length < 512 * 1024) {
						const bodyStr = buffer.toString();
						try {
							dataToSend.response = JSON.parse(bodyStr);
						} catch {
							dataToSend.responseBody = bodyStr.slice(0, 10000); // 限制长度
						}
					}
				})
				.catch(() => {})
				.then(() => {
					axios.post(`http://localhost:${process.env.PORT || 3000}/api/capture`, dataToSend)
						.catch(err => logger.error('Failed to send capture data:', err.message));
				});
		} else {
			// 没有响应体或非文本，直接发送基础信息
			axios.post(`http://localhost:${process.env.PORT || 3000}/api/capture`, dataToSend)
				.catch(err => logger.error('Failed to send capture data:', err.message));
		}
	}
};

hook.connect.before = (ctx) => {
	const { req } = ctx;
	const url = parse('https://' + req.url);
	const hostname = url.hostname || '';

	// 网易云域名: 走本地 MITM 代理 (原有逻辑)
	const isNetease = [url.hostname, req.headers.host].some((host) =>
		hook.target.host.has(host)
	);

	if (isNetease) {
		if (parseInt(url.port) === 80) {
			req.url = `${global.address || 'localhost'}:${global.port[0]}`;
			req.local = true;
		} else if (global.port[1]) {
			req.url = `${global.address || 'localhost'}:${global.port[1]}`;
			req.local = true;
		} else {
			ctx.decision = 'blank';
		}
	} else if (url.href.includes(global.endpoint)) {
		ctx.decision = 'proxy';
	} else if (isFullCapture()) {
		// 完整抓包模式: 非网易云域名也走本地 MITM 代理
		// 这样就能捕获所有 HTTPS 流量
		if (global.port[1]) {
			req.url = `${global.address || 'localhost'}:${global.port[1]}`;
			req.local = true;
		} else {
			ctx.decision = 'blank';
		}
	}
};

hook.negotiate.before = (ctx) => {
	const { req, socket, decision } = ctx;
	const url = parse('https://' + req.url);
	const target = hook.target.host;
	if (req.local || decision) return;
	// 完整抓包: 非网易云域名直接 MITM (sni 域名自动加入 target set)
	if (isFullCapture() && socket.sni && !target.has(socket.sni)) {
		target.add(socket.sni);
		ctx.decision = 'blank';
		return;
	}
	if (target.has(socket.sni) && !target.has(url.hostname)) {
		target.add(url.hostname);
		ctx.decision = 'blank';
	}
};

module.exports = hook;
