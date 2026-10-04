const net = require('net');
const parse = require('url').parse;
const crypto = require('./crypto');
const request = require('./request');
const xeapi = require('./xeapi');
const { isHost, cookieToMap, mapToCookie } = require('./utilities');
const { logScope } = require('./logger');
const axios = require('axios');
require('dotenv').config();

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

/**
 * 用缓存下来的响应体替换原始流。
 * 因为体已经被 request.read() 解压过了, 必须同时清掉与原始字节数/编码相关的头,
 * 否则客户端会按旧的 content-length / content-encoding 解析而报错。
 */
function setBufferedBody(proxyRes, buffer) {
	proxyRes.body = buffer;
	delete proxyRes.headers['content-encoding'];
	delete proxyRes.headers['content-length'];
	delete proxyRes.headers['transfer-encoding'];
}

/**
 * 响应体只能被读一次: 握手换包、网易云解密、通用抓包都要用, 这里统一缓存。
 * 注意读完必须把 body 写回去 (proxy.mitm.response 依赖它), 否则响应体会丢。
 */
function readBody(proxyRes) {
	if (!proxyRes._bodyPromise) {
		proxyRes._bodyPromise = request
			.read(proxyRes, true)
			.then((buffer) => {
				setBufferedBody(proxyRes, buffer);
				return buffer;
			})
			.catch((error) => {
				proxyRes._bodyError = error;
				return null;
			});
	}
	return proxyRes._bodyPromise;
}

/**
 * 拦截 xeapi 公钥响应: 把服务器公钥换成我们自己的, 并记下真实公钥用于转发
 */
function interceptKeyState(ctx) {
	const { req, proxyRes } = ctx;
	return readBody(proxyRes).then((buffer) => {
		const replaced = xeapi.replaceKeyResponse(
			parse(req.url || '').path,
			buffer
		);
		if (!replaced) return;
		setBufferedBody(proxyRes, replaced);
		ctx.keyExchange = true;
	});
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

	// 拉公钥的请求单独打一条 info 日志: 用来确认客户端的握手有没有真的走进代理。
	// (如果客户端某个原生网络栈绕过了代理, 这条日志就不会出现)
	if (xeapi.isKeyExchangePath(url.path)) {
		logger.info(
			{ path: url.path, host: url.hostname, method: req.method },
			'xeapi: 收到拉公钥请求 (即将在响应里替换公钥)'
		);
	}

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
						case 'xeapi': {
							// 新格式: B/C + S + R。S 是加密给「MITM 公钥」的 (握手响应已被换包),
							// 所以这里能直接解出动态密钥并解开 B/C; 同时要用真实公钥把 S 重新封装再转发上游。
							const info = xeapi.decryptRequest(body);
							if (info) {
								const parsed = xeapi.parsePlaintext(
									info.plaintext
								);
								netease.path = url.pathname;
								netease.param = parsed.param;
								netease.query = parsed.query;
								netease.e_r = true; // xeapi 的响应一定是 eapiKey 加密的
								netease.xeapi = {
									os: info.os,
									format: info.format,
									keyType: info.keyType,
									keyVersion: info.version,
									method: parsed.fields && parsed.fields.method,
									contentType:
										parsed.fields &&
										parsed.fields.contentType,
								};
								ctx.xeapiRewrite = xeapi
									.rewriteRequest(body, info)
									.then((newBody) => {
										if (newBody) {
											req.body = newBody;
											logger.debug(
												'xeapi: 已用真实公钥重新封装 S 转发上游'
											);
										}
										return null;
									});
							} else {
								// 解不开 (旧格式, 或客户端持有真实公钥): 至少把 URL query 展示出来
								netease.path = url.pathname;
								const queryParams = {};
								if (url.query) {
									const searchParams = new URLSearchParams(
										url.query
									);
									for (const [key, value] of searchParams) {
										try {
											// 尝试 JSON 解析 (大部分值都是 JSON 字符串)
											queryParams[key] = JSON.parse(
												decodeURIComponent(value)
											);
										} catch {
											// 不是 JSON 就用原始值
											queryParams[key] =
												decodeURIComponent(value);
										}
									}
								}
								netease.param = queryParams;
							}
							break;
						}
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
				// xeapi: 等 S 用真实公钥重新封装好再转发上游
				return ctx.xeapiRewrite;
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

const captureResponse = (ctx) => {
	const { req, proxyRes, netease, package: pkg } = ctx;

	if (netease) {
		// 计算请求耗时
		const duration = ctx.startTime ? Date.now() - ctx.startTime : 0;
		// 捕获响应头
		const responseHeaders = proxyRes ? { ...proxyRes.headers } : {};
		delete responseHeaders['transfer-encoding'];

		return readBody(proxyRes)
			.then((buffer) => {
				if (!buffer || !buffer.length) throw new Error('响应体为空');
				return buffer; // body 已由 readBody 写回 proxyRes
			})
			.then((buffer) => {
				const patch = (string) =>
					string.replace(
						/([^\\]"\s*:\s*)(\d{16,})(\s*[}|,])/g,
						'$1"$2L"$3'
					); // for js precision

				if (netease.e_r) {
					// 已知加密: 用 eapiKey 解密 (xeapi/eapi 响应都用 eapiKey), 明文可能是 gzip
					netease.jsonBody = JSON.parse(
						patch(crypto.xeapi.decryptResponseText(buffer))
					);
				} else {
					// 未知是否加密: 先尝试直接解析 JSON
					try {
						netease.jsonBody = JSON.parse(patch(buffer.toString()));
					} catch(e) {
						// 不是 JSON? 可能是加密的，尝试 eapi 解密 (xeapi 不解密请求参数时 e_r 未设)
						try {
							const decrypted = crypto.xeapi.decryptResponseText(buffer);
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
					query: netease.query || undefined,
					response: netease.jsonBody,
					statusCode: proxyRes.statusCode,
					method: req.method,
					duration,
					requestHeaders: ctx.requestHeaders,
					responseHeaders,
					isNetease: true,
					// xeapi 额外信息: 格式(BSR/CSR)、平台(PC/移动端)、密钥版本等
					xeapi: netease.xeapi || undefined,
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
					query: netease.query || undefined,
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
		const hasLength = /^\d+$/.test(String((proxyRes && proxyRes.headers['content-length']) || ''));
		const contentLength = hasLength ? parseInt(proxyRes.headers['content-length'], 10) : -1;

		// 只有长度已知且不大时才缓存: 长度未知 (chunked) 的响应不动它, 直接流式透传
		if (proxyRes && isTextResponse && hasLength && contentLength < 512 * 1024) {
			return readBody(proxyRes)
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

hook.request.after = (ctx) => {
	// xeapi 握手: 把响应里的服务器公钥换成我们自己的, 后续请求才解得开
	if (ctx.proxyRes && xeapi.isKeyExchangePath(parse(ctx.req.url || '').path)) {
		return interceptKeyState(ctx).then(() => {
			if (ctx.keyExchange) return null; // 已经改过包, 不再作为普通抓包展示
			return captureResponse(ctx);
		});
	}
	return captureResponse(ctx);
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

	// 排查用: 看着像网易云的域名却没走 MITM, 说明它不在 hook.target.host 名单里,
	// 会被透明透传 (抓不到也改不了包)。手机端拉公钥如果走的是陌生域名, 就会命中这里。
	if (
		!req.local &&
		!ctx.decision &&
		/163|music|netease|orpheus/i.test(`${req.url} ${req.headers.host || ''}`)
	) {
		logger.info(
			{ target: req.url, host: req.headers.host },
			'未走 MITM (透明透传): 该域名不在抓包名单里'
		);
	}
};

hook.negotiate.before = (ctx) => {
	const { req, socket, decision } = ctx;
	if (req.local || decision) return;
	const name = socket.sni;
	if (!name) return;

	// 客户端可能按 IP 直连过来 (App 用 HTTPDNS 自己解析, CONNECT 目标就是 IP),
	// 那样 connect.before 匹配不到域名, 已经连到真实服务器上了。
	// 但 TLS 的 SNI 仍然是真实域名, 而且客户端的首包 (ClientHello) 还压在我们手里没发出去,
	// 所以这里直接断掉直连、改接到本地 MITM 端口, 对客户端完全无感。
	const isTarget = hook.target.host.has(name) || isFullCapture();
	if (!isTarget || !global.port || !global.port[1]) return;

	if (ctx.proxySocket) {
		ctx.proxySocket.destroy();
		ctx.proxySocket = null;
	}
	req.url = `${global.address || 'localhost'}:${global.port[1]}`;
	req.local = true;
	logger.info(
		{ sni: name, connect: req.headers.host },
		'xeapi: 客户端按 IP 连接, 依据 SNI 改接本地 MITM'
	);
	return new Promise((resolve, reject) => {
		const localSocket = net
			.connect(global.port[1], global.address || 'localhost')
			.on('connect', () => resolve((ctx.proxySocket = localSocket)))
			.on('error', (error) => reject((ctx.error = error)));
	});
};

module.exports = hook;
