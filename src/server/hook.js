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

const logger = logScope('hook');

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
		req.method === 'POST' &&
		(url.path.startsWith('/eapi/') || // eapi
			url.path.startsWith('/xeapi/') || // xeapi
			url.path.startsWith('/api/linux/forward')) // linuxapi
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
				if (body) {
					const netease = {};
					netease.pad = (body.match(/%0+$/) || [''])[0];
					if (url.path === '/api/linux/forward') {
						netease.crypto = 'linuxapi';
					} else if (url.path.startsWith('/eapi/')) {
						netease.crypto = 'eapi';
					} else if (url.path.startsWith('/xeapi/')) {
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
							// 解析 B=...&S=...&R=... 格式 (新 xeapi 协议)
							const parsedBody = querystring.parse(body);
							const bField = parsedBody.B;
							const sField = parsedBody.S;
							
							if (!bField) {
								throw new Error('xeapi body missing B field');
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
							} else {
								// 无法解密 xeapi，但 URL 上的 query 参数就是请求参数喵！
								netease.path = url.pathname;
								const queryParams = {};
								if (url.query) {
									const searchParams = new URLSearchParams(url.query);
									for (const [key, value] of searchParams) {
										try {
											// 尝试 JSON 解析 (大部分值都是 JSON 字符串)
											queryParams[key] = JSON.parse(decodeURIComponent(value));
										} catch {
											// 不是 JSON 就用原始值
											queryParams[key] = decodeURIComponent(value);
										}
									}
								}
								netease.param = queryParams;
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

				if (netease.e_r) {
					// 已知加密: 用 eapiKey 解密 (xeapi/eapi 响应都用 eapiKey)
					netease.jsonBody = JSON.parse(
						patch(crypto.eapi.decrypt(buffer).toString())
					);
				} else {
					// 未知是否加密: 先尝试直接解析 JSON
					try {
						netease.jsonBody = JSON.parse(patch(buffer.toString()));
					} catch(e) {
						// 不是 JSON? 可能是加密的，尝试 eapi 解密 (xeapi 不解密请求参数时 e_r 未设)
						try {
							const decrypted = crypto.eapi.decrypt(buffer).toString();
							netease.jsonBody = JSON.parse(patch(decrypted));
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