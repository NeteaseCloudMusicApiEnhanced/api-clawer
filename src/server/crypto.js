'use strict';

const crypto = require('crypto');
const zlib = require('zlib');
const parse = require('url').parse;
const bodyify = require('querystring').stringify;

const eapiKey = 'e82ckenh8dichen8';
const linuxapiKey = 'rFgB&h#%2?^eDg:Q';

// xeapi 静态密钥: PC 端与移动端不同
const xeapiStaticKeys = {
	mobile: Buffer.from(
		'ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84',
		'hex'
	),
	pc: Buffer.from(
		'hw7WBGc5HWCZzhBM50P3pDvtn/RzxDy+FW+wygIErn4=',
		'base64'
	),
};

const xeapiStaticKey = xeapiStaticKeys.mobile;

// 旧版 xeapi 密钥 (16字节，兼容旧格式)
const xeapiOldKey = Buffer.from('723f08a8d77c4a3698a9722b71b3607b', 'hex');

// X25519 SPKI 前缀
const x25519SpkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');

const decrypt128Ecb = (buffer, key) => {
	const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
	return Buffer.concat([decipher.update(buffer), decipher.final()]);
};

const encrypt128Ecb = (buffer, key) => {
	const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
	return Buffer.concat([cipher.update(buffer), cipher.final()]);
};

const decrypt256Ecb = (buffer, key) => {
	const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
	return Buffer.concat([decipher.update(buffer), decipher.final()]);
};

/**
 * 按密钥长度自动选 AES-128/192/256-ECB。
 * xeapi 请求体最外层的动态密钥有两种长度:
 *   - 16 字节: 客户端随机生成的动态密钥 (AES-128)
 *   - 32 字节: 服务器通过响应头 x-encr-sskey 下发的会话密钥, 客户端直接当 AES-256 密钥用
 * 写死 AES-128 会在会话模式下抛 "Invalid key length", 导致整批请求都解不开。
 */
const decryptEcbAuto = (buffer, key) => {
	const decipher = crypto.createDecipheriv(
		`aes-${key.length * 8}-ecb`,
		key,
		null
	);
	return Buffer.concat([decipher.update(buffer), decipher.final()]);
};

const encrypt256Ecb = (buffer, key) => {
	const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
	return Buffer.concat([cipher.update(buffer), cipher.final()]);
};

// xeapi Mid Transform: 前 16 字节随机数 XOR + 字节轮转
const xeapiMidTransform = (ciphertext) => {
	const random = crypto.randomBytes(16);
	const xored = Buffer.alloc(ciphertext.length);
	for (let i = 0; i < ciphertext.length; i++) {
		xored[i] = ciphertext[i] ^ random[i & 0x0f];
	}
	const rot = xored.length ? (random[0] & 0x0f) % xored.length : 0;
	return Buffer.concat([random, xored.subarray(rot), xored.subarray(0, rot)]);
};

// 逆 Mid Transform
const xeapiMidUntransform = (transformed) => {
	const random = transformed.subarray(0, 16);
	const body = transformed.subarray(16);
	const rot = body.length ? (random[0] & 0x0f) % body.length : 0;
	const xored = Buffer.concat([
		body.subarray(body.length - rot),
		body.subarray(0, body.length - rot),
	]);
	const plain = Buffer.alloc(xored.length);
	for (let i = 0; i < xored.length; i++) {
		plain[i] = xored[i] ^ random[i & 0x0f];
	}
	return plain;
};

// xeapi 握手签名密钥 (HMAC-SHA256(timestamp + nonce))
// xeapi 握手签名密钥 (HMAC-SHA256(timestamp + nonce)), 同样分 PC / 移动端
const xeapiSignKeys = {
	mobile:
		'mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g==',
	pc: 'YN6+QFyG6D3rc3J1VT6sqwaPKE+GdwxtDweGmEPklcgrEohaE60m4Y/TtI4R/vVi17JUwwCIQF0Q2FXFmMlGrg==',
};

const xeapiSignKey = xeapiSignKeys.mobile;

const isRawX25519 = (raw) => Buffer.isBuffer(raw) && raw.length === 32;

// 由 32 字节原始公钥构造 KeyObject
const createX25519PublicKey = (raw) =>
	crypto.createPublicKey({
		key: Buffer.concat([x25519SpkiPrefix, raw]),
		format: 'der',
		type: 'spki',
	});

// X25519 PKCS#8 固定前缀, 用于把 32 字节原始私钥包装成 KeyObject
const x25519Pkcs8Prefix = Buffer.from('302e020100300506032b656e04220420', 'hex');

const createX25519PrivateKey = (raw) =>
	crypto.createPrivateKey({
		key: Buffer.concat([x25519Pkcs8Prefix, raw]),
		format: 'der',
		type: 'pkcs8',
	});

// 取出 KeyObject 里的 32 字节原始公钥
const rawX25519PublicKey = (keyObject) =>
	Buffer.from(keyObject.export({ format: 'der', type: 'spki' })).subarray(-32);

// HKDF-SHA256(salt=0, info=ephemeral公钥||0x01) → 16 字节 AES-128 密钥
const deriveX25519AesKey = (sharedSecret, ephemeralPublicKey) => {
	const prk = crypto
		.createHmac('sha256', Buffer.alloc(32))
		.update(sharedSecret.length ? sharedSecret : Buffer.alloc(32))
		.digest();
	return crypto
		.createHmac('sha256', prk)
		.update(Buffer.concat([ephemeralPublicKey, Buffer.from([1])]))
		.digest()
		.subarray(0, 16);
};

// base64 / base64url 兼容解码
const decodeBase64Flexible = (value) =>
	Buffer.from(String(value).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

// 封装 S 字段 (发给持有 serverPublicKeyRaw 的一方)
// 结构: ephemeralPub(32) | iv(12) | AES-128-GCM 密文 | tag(16)
// 明文: `${base64(dynamicKey)}|${os}|${sk}`
const xeapiEncryptS = (dynamicKey, serverPublicKeyRaw, sk, os = 'android') => {
	const peerKey = createX25519PublicKey(serverPublicKeyRaw);
	const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
	const ephemeralRaw = rawX25519PublicKey(publicKey);
	const sharedSecret = crypto.diffieHellman({ privateKey, publicKey: peerKey });
	const aesKey = deriveX25519AesKey(sharedSecret, ephemeralRaw);
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
	const plaintext = Buffer.from(
		`${dynamicKey.toString('base64')}|${os}|${sk || ''}`
	);
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	return Buffer.concat([ephemeralRaw, iv, encrypted, cipher.getAuthTag()]);
};

// 解密 S 字段 (用接收方自己的 X25519 私钥)
// 返回动态密钥以及明文里的 os / sk 戳记
const xeapiDecryptS = (sBuffer, privateKey) => {
	const ephemeralRaw = sBuffer.subarray(0, 32);
	const iv = sBuffer.subarray(32, 44);
	const authTag = sBuffer.subarray(sBuffer.length - 16);
	const ciphertext = sBuffer.subarray(44, sBuffer.length - 16);

	const sharedSecret = crypto.diffieHellman({
		privateKey,
		publicKey: createX25519PublicKey(ephemeralRaw),
	});
	const aesKey = deriveX25519AesKey(sharedSecret, ephemeralRaw);

	const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
	decipher.setAuthTag(authTag);
	const text = Buffer.concat([
		decipher.update(ciphertext),
		decipher.final(),
	]).toString();

	const [dynamicKey, os, sk] = text.split('|');
	return { dynamicKey: Buffer.from(dynamicKey, 'base64'), os, sk, text };
};

// 旧 BSR 格式的逆变换: 轮转的是 base64 文本 (与新 CSR 轮转原始字节不同)
const xeapiMidUntransformLegacy = (transformed) => {
	const random = transformed.subarray(0, 16);
	const b64Part = transformed.subarray(16);
	const actualRot = b64Part.length
		? (random[0] & 0x0f) % b64Part.length
		: 0;
	const unrotated = Buffer.concat([
		b64Part.subarray(b64Part.length - actualRot),
		b64Part.subarray(0, b64Part.length - actualRot),
	]);
	const xored = Buffer.from(unrotated.toString(), 'base64');
	const plain = Buffer.alloc(xored.length);
	for (let i = 0; i < xored.length; i++) {
		plain[i] = xored[i] ^ random[i & 0x0f];
	}
	return plain;
};

const looksLikeJson = (text) => /^\s*[{[]/.test(text);

/**
 * 解密 xeapi 请求体, 同时兼容两种格式和两套静态密钥:
 *   - CSR: 字段 C, base64url, Mid Transform 轮转原始字节
 *   - BSR (旧): 字段 B, base64,    Mid Transform 轮转 base64 文本
 * 注意: 格式 (BSR/CSR) 与平台无关, BSR/CSR 都可能来自 PC 或移动端;
 * 平台只由「哪把静态密钥解得开」决定 (PC 与移动端静态密钥不同)。
 * S 字段结构两边一致, 差别只在 B/C 的变换方式和静态密钥, 所以组合起来都试一遍。
 * S  → 动态密钥; B/C → AES-128-ECB(动态密钥) → 逆 Mid Transform → AES-256-ECB(静态密钥)
 */
const xeapiDecryptRequest = (fields, privateKey) => {
	const cField = fields.C || fields.B;
	if (!cField) throw new Error('xeapi 请求体缺少 B/C 字段');
	if (!fields.S) throw new Error('xeapi 请求体缺少 S 字段');

	const { dynamicKey, os, sk } = xeapiDecryptS(
		decodeBase64Flexible(fields.S),
		privateKey
	);
	const mid = decryptEcbAuto(decodeBase64Flexible(cField), dynamicKey);

	// 字段名只是「先试哪种变换」的提示 (C → 字节轮转, B → base64 文本轮转), 试错会自动兜底
	const transforms = fields.C
		? [
				['bytes', xeapiMidUntransform],
				['base64-text', xeapiMidUntransformLegacy],
			]
		: [
				['base64-text', xeapiMidUntransformLegacy],
				['bytes', xeapiMidUntransform],
			];

	let lastError = null;
	for (const [transform, untransform] of transforms) {
		for (const [keyType, staticKey] of Object.entries(xeapiStaticKeys)) {
			try {
				const plaintext = decrypt256Ecb(
					untransform(mid),
					staticKey
				).toString();
				if (!looksLikeJson(plaintext))
					throw new Error('解密结果不是 JSON');
				return {
					plaintext,
					dynamicKey,
					os,
					sk,
					format: fields.C ? 'CSR' : 'BSR',
					transform,
					keyType,
				};
			} catch (error) {
				lastError = error;
			}
		}
	}
	throw new Error(
		`xeapi 请求体解密失败: ${lastError && lastError.message}`
	);
};


// 用真实服务器公钥重新封装 S (其余字段与动态密钥保持原样, 服务器才能解开)
const xeapiReencryptS = (dynamicKey, realPublicKeyRaw, sk, os) =>
	xeapiEncryptS(dynamicKey, realPublicKeyRaw, sk, os).toString('base64');


// xeapi 响应: AES-128-ECB(eapiKey), 明文可能是 gzip
const xeapiResDecryptText = (buffer) => {
	const decrypted = decrypt128Ecb(buffer, eapiKey);
	const plaintext =
		decrypted[0] === 0x1f && decrypted[1] === 0x8b
			? zlib.gunzipSync(decrypted)
			: decrypted;
	return plaintext.toString();
};

const xeapiResDecrypt = (buffer) => JSON.parse(xeapiResDecryptText(buffer));

/**
 * 握手响应里的 encryptedData: AES-256-ECB(静态密钥) 包裹的服务器公钥状态
 * 两套静态密钥都试, 并返回是哪一个 (替换公钥后必须用同一把再加密回去)
 */
const xeapiDecryptKeyStateWithKey = (encryptedData) => {
	const raw = Buffer.from(String(encryptedData), 'base64');
	let lastError = null;
	for (const [keyType, staticKey] of Object.entries(xeapiStaticKeys)) {
		try {
			return {
				state: JSON.parse(decrypt256Ecb(raw, staticKey).toString()),
				keyType,
			};
		} catch (error) {
			lastError = error;
		}
	}
	throw new Error(
		`xeapi 公钥状态解密失败: ${lastError && lastError.message}`
	);
};

const xeapiDecryptKeyState = (encryptedData) =>
	xeapiDecryptKeyStateWithKey(encryptedData).state;

const xeapiEncryptKeyState = (keyState, keyType = 'mobile') =>
	encrypt256Ecb(
		Buffer.from(JSON.stringify(keyState)),
		xeapiStaticKeys[keyType] || xeapiStaticKey
	).toString('base64');

// R 字段: 静态密钥加密的 `${version}|${sessionId}` (同样两套都要试)
const xeapiDecryptR = (rField) => {
	const raw = decodeBase64Flexible(rField);
	let lastError = null;
	for (const staticKey of Object.values(xeapiStaticKeys)) {
		try {
			return decrypt256Ecb(raw, staticKey).toString();
		} catch (error) {
			lastError = error;
		}
	}
	throw lastError;
};

const xeapiEncryptR = (version, sessionId = '', keyType = 'mobile') =>
	encrypt256Ecb(
		Buffer.from(`${version}|${sessionId}`),
		xeapiStaticKeys[keyType] || xeapiStaticKey
	).toString('base64');

const xeapiSign = (timestamp, nonce, keyType = 'mobile') =>
	crypto
		.createHmac('sha256', xeapiSignKeys[keyType] || xeapiSignKey)
		.update(String(timestamp) + nonce)
		.digest('base64');

module.exports = {
	eapi: {
		encrypt: (buffer) => encrypt128Ecb(buffer, eapiKey),
		decrypt: (buffer) => decrypt128Ecb(buffer, eapiKey),
		encryptRequest: (url, object) => {
			url = parse(url);
			const text = JSON.stringify(object);
			const message = `nobody${url.path}use${text}md5forencrypt`;
			const digest = crypto
				.createHash('md5')
				.update(message)
				.digest('hex');
			const data = `${url.path}-36cd479b6b5-${text}-36cd479b6b5-${digest}`;
			return {
				url: url.href.replace(/\w*api/, 'eapi'),
				body: bodyify({
					params: module.exports.eapi
						.encrypt(Buffer.from(data))
						.toString('hex')
						.toUpperCase(),
				}),
			};
		},
	},
	xeapi: {
		// 旧格式 (纯 AES-128-ECB), 仅供兼容
		encrypt: (buffer) => encrypt128Ecb(buffer, xeapiOldKey),
		decrypt: (buffer) => decrypt128Ecb(buffer, xeapiOldKey),
		// X25519 密钥交换 + 双层 AES (新格式)
		createX25519PublicKey,
		createX25519PrivateKey,
		rawX25519PublicKey,
		encryptS: xeapiEncryptS,
		decryptS: xeapiDecryptS,
		decryptRequest: xeapiDecryptRequest,
		reencryptS: xeapiReencryptS,
		decryptR: xeapiDecryptR,
		encryptR: xeapiEncryptR,
		// 响应 / 公钥状态
		decryptResponse: xeapiResDecrypt,
		decryptResponseText: xeapiResDecryptText,
		decryptKeyState: xeapiDecryptKeyState,
		decryptKeyStateWithKey: xeapiDecryptKeyStateWithKey,
		encryptKeyState: xeapiEncryptKeyState,
		sign: xeapiSign,
		staticKeyTypes: Object.keys(xeapiStaticKeys),
		encryptRequest: (url, object) => {
			url = parse(url);
			const text = JSON.stringify(object);
			const message = `nobody${url.path}use${text}md5forencrypt`;
			const digest = crypto
				.createHash('md5')
				.update(message)
				.digest('hex');
			const data = `${url.path}-36cd479b6b5-${text}-36cd479b6b5-${digest}`;
			return {
				url: url.href.replace(/\w*api/, 'xeapi'),
				body: bodyify({
					params: module.exports.xeapi
						.encrypt(Buffer.from(data))
						.toString('hex')
						.toUpperCase(),
				}),
			};
		},
	},
	api: {
		encryptRequest: (url, object) => {
			url = parse(url);
			return {
				url: url.href.replace(/\w*api/, 'api'),
				body: bodyify(object),
			};
		},
	},
	linuxapi: {
		encrypt: (buffer) => encrypt128Ecb(buffer, linuxapiKey),
		decrypt: (buffer) => decrypt128Ecb(buffer, linuxapiKey),
		encryptRequest: (url, object) => {
			url = parse(url);
			const text = JSON.stringify({
				method: 'POST',
				url: url.href,
				params: object,
			});
			return {
				url: url.resolve('/api/linux/forward'),
				body: bodyify({
					eparams: module.exports.linuxapi
						.encrypt(Buffer.from(text))
						.toString('hex')
						.toUpperCase(),
				}),
			};
		},
	},
	base64: {
		encode: (text, charset) =>
			Buffer.from(text, charset)
				.toString('base64')
				.replace(/\+/g, '-')
				.replace(/\//g, '_'),
		decode: (text, charset) =>
			Buffer.from(
				text.replace(/-/g, '+').replace(/_/g, '/'),
				'base64'
			).toString(charset),
	},
	md5: {
		digest: (value) => crypto.createHash('md5').update(value).digest('hex'),
		pipe: (source) =>
			new Promise((resolve, reject) => {
				const digest = crypto.createHash('md5').setEncoding('hex');
				source
					.pipe(digest)
					.on('error', (error) => reject(error))
					.once('finish', () => resolve(digest.read()));
			}),
	},
	sha1: {
		digest: (value) =>
			crypto.createHash('sha1').update(value).digest('hex'),
	},
	random: {
		hex: (length) =>
			crypto
				.randomBytes(Math.ceil(length / 2))
				.toString('hex')
				.slice(0, length),
		uuid: () => crypto.randomUUID(),
	},
};