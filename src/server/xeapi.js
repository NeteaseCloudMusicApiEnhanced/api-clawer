'use strict';

/**
 * xeapi 抓包 MITM
 *
 * 网易云 xeapi 协议里, 客户端先拉一次「服务器公钥状态」(AES-256-ECB + 静态密钥包裹),
 * 拉取路径只有两个: /api/bsr/sk/get 和 /api/gorilla/anti/crawler/security/key/get。
 * 之后每个业务请求:
 *   - S: 用服务器 X25519 公钥加密的会话材料, 明文是 base64(动态密钥)|os|sk
 *   - B/C: 用动态密钥 (AES-128-ECB) + Mid Transform + 静态密钥 (AES-256-ECB) 加密的请求体
 *   - R: 静态密钥加密的 `version|sessionId`
 *
 * 请求体有 BSR / CSR 两个版本 (可以理解成同一个 API 的两代格式), 它们和平台无关:
 *   BSR: 字段 B, base64,   Mid Transform 轮转 base64 文本
 *   CSR: 字段 C, base64url, Mid Transform 轮转原始字节
 * 平台 (PC / 移动端) 只体现在「静态密钥不同」上, 所以平台由哪把静态密钥解得开来决定,
 * 不能靠 BSR/CSR 或路径来判断。
 *
 * 我们当然拿不到服务器私钥, 所以做法是:
 *   1. 拦下公钥响应, 把里面的服务器公钥换成我们自己的 X25519 公钥, 再用同一把
 *      静态密钥包好发回客户端 (整包没有 MAC, 客户端无法察觉);
 *   2. 客户端于是把 S 加密给「我们」, 我们用自己的私钥就能取出动态密钥, 从而解密 B/C;
 *   3. 转发上游时, 用第 1 步记下的「同平台」真实公钥把 S 重新封装 (动态密钥/os/sk 原样保留),
 *      服务器那边完全感知不到, B/C、R 直接透传。
 *
 * 响应方向不需要改包: 响应是 AES-128-ECB(eapiKey) 加密的 (明文可能是 gzip),
 * 我们只要能解密出内容展示即可, 客户端本来就能解。
 */

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');
const querystring = require('querystring');

const { logScope } = require('./logger');
const { xeapi, eapi } = require('./crypto');

const logger = logScope('xeapi');

const apiDomain = process.env.XEAPI_API_DOMAIN || 'interface.music.163.com';
// 拉取公钥的接口
// 注意: 拉公钥的请求本身也可能被 eapi/xeapi 包一层
// 所以比较时抹掉前缀, 只看后缀。
const keyEndpoints = [
	'gorilla/anti/crawler/security/key/get',
	'bsr/sk/get',
];

const isKeyExchangePath = (pathname) => {
	const path = String(pathname || '')
		.split('?')[0]
		.replace(/\/+$/, '')
		.replace(/^\/(api|eapi|xeapi)\//i, '')
		.toLowerCase();
	return keyEndpoints.includes(path);
};

// ---------------------------------------------------------------- MITM 密钥对

/**
 * 由 CA 私钥 (server.key) 确定性派生我们的 X25519 密钥对。
 * 这样代理重启后公钥不变, 客户端不用重新握手; server.key 换掉也只是重新握手一次。
 */
let mitmKeyPair = null;

const deriveMitmKeyPair = () => {
	const keyPath = process.env.SIGN_KEY || path.join(__dirname, 'server.key');
	try {
		const caKey = crypto.createPrivateKey(fs.readFileSync(keyPath));
		const der = caKey.export({ format: 'der', type: 'pkcs8' });
		const seed = Buffer.from(
			crypto.hkdfSync(
				'sha256',
				der,
				'api-clawer/xeapi-mitm',
				'x25519-private-key',
				32
			)
		);
		const privateKey = xeapi.createX25519PrivateKey(seed);
		return {
			privateKey,
			raw: xeapi.rawX25519PublicKey(crypto.createPublicKey(privateKey)),
		};
	} catch (error) {
		logger.warn(
			{ error: error.message },
			'xeapi: 无法从 server.key 派生 MITM 密钥, 本次运行改用临时密钥 (客户端重启后需重新握手)'
		);
		const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
		return { privateKey, raw: xeapi.rawX25519PublicKey(publicKey) };
	}
};

const getMitmKeyPair = () => (mitmKeyPair = mitmKeyPair || deriveMitmKeyPair());

/** 我们对外冒充服务器时使用的公钥 (base64) */
const mitmPublicKeyBase64 = () => getMitmKeyPair().raw.toString('base64');

// ------------------------------------------------------- 服务器真实公钥登记表

// 自拉取公钥时用的平台参数 (响应会用哪个平台的静态密钥包裹, 取决于这里的 os/signKey)
const platforms = {
	mobile: {
		os: 'android',
		appVersion: '9.5.61',
		path: '/api/bsr/sk/get',
		ua: 'NeteaseMusic/9.5.61.260802021928(9005061);Dalvik/2.1.0 (Linux; U; Android 12; HBN-AL00 Build/cd737a2.0)',
	},
	pc: {
		os: 'pc',
		appVersion: '3.1.41',
		path: '/api/gorilla/anti/crawler/security/key/get',
		ua: 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.7977.130 Electron/44.5.1 Safari/537.36 NeteaseMusicDesktop/3.1.41.205529',
	},
};

/** @type {{publicKey: string, sk: string, version: string, keyType: string, nextUpdateTime?: number, at: number, source: string}[]} */
const realKeys = [];
let realKeyFetching = null;

const rememberRealKey = (state, source, keyType = 'mobile') => {
	if (!state || !state.publicKey) return null;
	const entry = {
		publicKey: state.publicKey,
		sk: state.sk || '',
		version: state.version || '',
		keyType,
		nextUpdateTime: state.nextUpdateTime || 0,
		at: Date.now(),
		source,
	};
	// 同一平台 + 同一公钥只留一条
	const index = realKeys.findIndex(
		(item) =>
			item.publicKey === entry.publicKey && item.keyType === entry.keyType
	);
	if (index !== -1) realKeys.splice(index, 1);
	realKeys.unshift(entry);
	if (realKeys.length > 8) realKeys.pop();
	logger.info(
		{ version: entry.version, keyType, source },
		'xeapi: 已记录服务器真实公钥'
	);
	return entry;
};

/**
 * sk 精确匹配 → version 匹配 → 同平台最新一条。
 * 这里不做「随便取最新」的兜底: 拿错平台的公钥去复加密会让请求彻底失败,
 * 找不到就返回 null, 让调用方原样透传。
 */
const findRealKey = ({ sk, version, keyType } = {}) => {
	if (!realKeys.length) return null;
	if (sk) {
		const bySk = realKeys.find((item) => item.sk && item.sk === sk);
		if (bySk) return bySk;
	}
	if (version) {
		const byVersion = realKeys.find((item) => item.version === version);
		if (byVersion) return byVersion;
	}
	if (keyType) {
		const byType = realKeys.find((item) => item.keyType === keyType);
		if (byType) return byType;
	}
	return null;
};

/**
 * 兜底: 客户端在代理启动前就握过手的话, 我们没见过响应, 只能自己拉一次真实公钥
 */
const fetchRealKey = (keyType = 'mobile') =>
	new Promise((resolve, reject) => {
		const platform = platforms[keyType] || platforms.mobile;
		const nonce = Array.from({ length: 16 }, () =>
			Math.floor(Math.random() * 10)
		).join('');
		const timestamp = String(Date.now());
		const body = querystring.stringify({
			appVersion: platform.appVersion,
			currentKeyVersion: '',
			deviceId: '',
			nonce,
			os: platform.os,
			requestType: 'active',
			signature: xeapi.sign(timestamp, nonce, keyType),
			t1: '',
			t2: '',
			timestamp,
			uid: '',
		});
		const request = https.request(
			{
				method: 'POST',
				hostname: apiDomain,
				path: platform.path,
				timeout: 10000,
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					'Content-Length': Buffer.byteLength(body),
					'User-Agent': platform.ua,
				},
			},
			(response) => {
				const chunks = [];
				response.on('data', (chunk) => chunks.push(chunk));
				response.on('end', () => {
					try {
						const json = JSON.parse(Buffer.concat(chunks).toString());
						if (!json.data || !json.data.encryptedData)
							throw new Error(`握手返回异常: code=${json.code}`);
						const { state, keyType: detected } =
							xeapi.decryptKeyStateWithKey(
								json.data.encryptedData
							);
						rememberRealKey(state, 'self-fetch', detected);
						resolve(findRealKey({ keyType }));
					} catch (error) {
						reject(error);
					}
				});
			}
		);
		request.on('timeout', () => request.destroy(new Error('请求超时')));
		request.on('error', reject);
		request.end(body);
	});

const ensureRealKey = ({ sk, version, keyType } = {}) => {
	const known = findRealKey({ sk, version, keyType });
	if (known) return Promise.resolve(known);
	if (realKeyFetching) return realKeyFetching;
	realKeyFetching = fetchRealKey(keyType)
		.catch((error) => {
			logger.warn({ error: error.message }, 'xeapi: 主动获取服务器公钥失败');
			return null;
		})
		.then((result) => {
			realKeyFetching = null;
			return result;
		});
	return realKeyFetching;
};

// ------------------------------------------------------------ 响应方向: 换公钥

/** 是不是带 encryptedData 的公钥状态响应 */
const isKeyStateJson = (json) =>
	!!(json && json.data && typeof json.data.encryptedData === 'string');

/**
 * 握手响应体可能是明文 JSON, 也可能是 eapi 加密的 JSON (取决于客户端加密状态)
 * @returns {null | {json: object, encrypted: boolean}}
 */
const parseKeyResponse = (buffer) => {
	try {
		const json = JSON.parse(buffer.toString());
		if (isKeyStateJson(json)) return { json, encrypted: false };
	} catch {
		// 不是明文 JSON, 继续试 eapi
	}
	try {
		const json = JSON.parse(xeapi.decryptResponseText(buffer));
		if (isKeyStateJson(json)) return { json, encrypted: true };
	} catch {
		// 也不是 eapi 密文
	}
	return null;
};

/** 换完公钥后按原来的编码方式写回去 */
const encodeKeyResponse = ({ json, encrypted }) =>
	encrypted
		? eapi.encrypt(Buffer.from(JSON.stringify(json)))
		: Buffer.from(JSON.stringify(json));

/**
 * 拦截拉公钥的响应: 命中接口就换公钥, 其余路径 / 非公钥响应返回 null (原样透传)
 * @param {string} pathname 请求路径 (可能是 /api、/eapi 或 /xeapi 前缀)
 * @param {Buffer} buffer 响应体原始字节
 * @returns {Buffer|null} 换包后的响应体
 */
const replaceKeyResponse = (pathname, buffer) => {
	if (!isKeyExchangePath(pathname)) return null;
	if (!buffer || !buffer.length) return null;
	const parsed = parseKeyResponse(buffer);
	if (!parsed) return null;
	if (!swapKeyState(parsed.json)) return null;
	return encodeKeyResponse(parsed);
};

/**
 * 把响应里的服务器公钥替换成我们的, 并把真实公钥记下来
 * 注意: 必须用「服务器原来用的那把静态密钥」重新加密回去, PC / 移动端各一把
 * @returns {boolean} 是否替换成功
 */
const swapKeyState = (json) => {
	try {
		const { state, keyType } = xeapi.decryptKeyStateWithKey(
			json.data.encryptedData
		);
		if (!state || !state.publicKey) return false;
		if (!/^[A-Za-z0-9+/=_-]{40,}$/.test(String(state.publicKey)))
			return false;
		rememberRealKey(state, 'client', keyType);
		json.data.encryptedData = xeapi.encryptKeyState(
			{
				...state,
				publicKey: mitmPublicKeyBase64(),
			},
			keyType
		);
		logger.info(
			{ version: state.version, keyType },
			'xeapi: 已把服务器公钥替换为本地 MITM 公钥'
		);
		return true;
	} catch (error) {
		logger.warn({ error: error.message }, 'xeapi: 公钥状态解密失败');
		return false;
	}
};

// ------------------------------------------------------------ 请求方向: 解密

const parseBodyFields = (body) => {
	const text = String(body || '').trim();
	if (!text) return null;
	if (text.startsWith('{')) {
		try {
			const json = JSON.parse(text);
			return { fields: json, json: true, raw: text };
		} catch {
			return null;
		}
	}
	return { fields: querystring.parse(text), json: false, raw: text };
};

/** 看起来像不像 xeapi 密文请求体 */
const looksLikeXeapiBody = (fields) =>
	!!fields && !!fields.S && !!(fields.C || fields.B);

const readVersionFromR = (rField) => {
	try {
		return xeapi.decryptR(rField).split('|')[0] || '';
	} catch {
		return '';
	}
};

/**
 * 解密 xeapi 请求体 (同步)
 * @returns {null | {plaintext: string, dynamicKey: Buffer, os: string, sk: string, version: string, fields: object, json: boolean}}
 */
const decryptRequest = (body) => {
	const parsed = parseBodyFields(body);
	if (!parsed || !looksLikeXeapiBody(parsed.fields)) return null;
	const { fields } = parsed;

	let decrypted;
	try {
		decrypted = xeapi.decryptRequest(fields, getMitmKeyPair().privateKey);
	} catch (error) {
		// 典型场景: 客户端在代理启动前就拿到了真实公钥, S 是加密给服务器的
		logger.warn(
			{ error: error.message },
			'xeapi: 请求体无法解密 (客户端可能持有真实公钥, 重启客户端即可重新走 MITM 握手)'
		);
		return null;
	}

	return {
		plaintext: decrypted.plaintext,
		dynamicKey: decrypted.dynamicKey,
		os: decrypted.os,
		sk: decrypted.sk,
		version: fields.R ? readVersionFromR(fields.R) : '',
		format: decrypted.format,
		transform: decrypted.transform,
		keyType: decrypted.keyType,
		fields,
		json: parsed.json,
	};
};

/** 解析解密后的请求明文 (官方结构: {queryString, content|body, contentType, method}) */
const parsePlaintext = (plaintext) => {
	let fields;
	try {
		fields = JSON.parse(plaintext);
	} catch {
		return { param: null, query: null, raw: plaintext };
	}
	let buffer = null;
	if (typeof fields.content === 'string') buffer = Buffer.from(fields.content);
	else if (typeof fields.body === 'string')
		buffer = Buffer.from(fields.body, 'base64');

	const isForm =
		!fields.contentType ||
		String(fields.contentType).includes('x-www-form-urlencoded');
	let param = null;
	if (buffer && isForm) {
		const map = {};
		for (const [key, value] of new URLSearchParams(buffer.toString()))
			map[key] = value;
		param = map;
	} else if (buffer) {
		try {
			param = JSON.parse(buffer.toString());
		} catch {
			param = buffer.toString();
		}
	}
	const query = fields.queryString
		? Object.fromEntries(new URLSearchParams(fields.queryString))
		: null;
	return { fields, param, query, raw: plaintext, hasBody: !!buffer };
};

/**
 * 用真实公钥重新封装 S, 其余字段原样透传后转发上游
 * @returns {Promise<string|null>} 新的请求体 (null 表示原样转发)
 */
const rewriteRequest = (body, info) => {
	if (!info) return Promise.resolve(null);
	return ensureRealKey({
		sk: info.sk,
		version: info.version,
		keyType: info.keyType,
	}).then((realKey) => {
		if (!realKey) {
			logger.warn(
				{ keyType: info.keyType, version: info.version },
				'xeapi: 没拿到该平台(PC/移动端)的服务器真实公钥, 该请求原样转发'
			);
			return null;
		}
		try {
			const newS = xeapi.reencryptS(
				info.dynamicKey,
				Buffer.from(realKey.publicKey, 'base64'),
				info.sk,
				info.os
			);
			if (info.json) return JSON.stringify({ ...info.fields, S: newS });
			const source = String(body);
			if (!/(^|&)S=/.test(source)) return null;
			return source.replace(
				/(^|&)S=[^&]*/,
				(match, prefix) => `${prefix}S=${encodeURIComponent(newS)}`
			);
		} catch (error) {
			logger.warn({ error: error.message }, 'xeapi: 请求体复加密失败');
			return null;
		}
	});
};

module.exports = {
	mitmPublicKeyBase64,
	isKeyExchangePath,
	isKeyStateJson,
	parseKeyResponse,
	encodeKeyResponse,
	replaceKeyResponse,
	swapKeyState,
	looksLikeXeapiBody,
	decryptRequest,
	parsePlaintext,
	rewriteRequest,
	ensureRealKey,
	findRealKey,
	parseBodyFields,
};
