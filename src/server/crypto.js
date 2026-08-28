'use strict';

const crypto = require('crypto');
const zlib = require('zlib');
const parse = require('url').parse;
const bodyify = require('querystring').stringify;

const eapiKey = 'e82ckenh8dichen8';
const linuxapiKey = 'rFgB&h#%2?^eDg:Q';

// xeapi 静态密钥 (32字节，AES-256-ECB)
const xeapiStaticKey = Buffer.from(
  'ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84',
  'hex',
);

// 旧版 xeapi 密钥 (16字节，兼容旧格式)
const xeapiOldKey = Buffer.from('723f08a8d77c4a3698a9722b71b3607b', 'hex');

// X25519 SPKI 前缀
const x25519SpkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');

// xeapi 签名密钥 (key/get 响应验签用)
const xeapiSignKey =
	'mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g==';

// xeapi 签名 (参考 api-enhanced)
const xeapiSign = (timestamp, nonce) => {
	return crypto
		.createHmac('sha256', xeapiSignKey)
		.update(String(timestamp) + nonce)
		.digest('base64');
};

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

const encrypt256Ecb = (buffer, key) => {
	const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
	return Buffer.concat([cipher.update(buffer), cipher.final()]);
};

// xeapi Mid Transform: XOR + base64 rotation
const xeapiMidTransform = (ciphertext) => {
	const random = crypto.randomBytes(16);
	const xored = Buffer.alloc(ciphertext.length);
	for (let i = 0; i < ciphertext.length; i++) {
		xored[i] = ciphertext[i] ^ random[i & 0x0f];
	}
	const b64 = Buffer.from(xored.toString('base64'));
	const rot = b64.length ? (random[0] & 0x0f) % b64.length : 0;
	return Buffer.concat([random, b64.subarray(rot), b64.subarray(0, rot)]);
};

// 逆 Mid Transform
const xeapiMidUntransform = (transformed) => {
	const random = transformed.subarray(0, 16);
	const b64Part = transformed.subarray(16);
	const rot = random[0] & 0x0f;
	const actualRot = b64Part.length ? rot % b64Part.length : 0;
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

// 解密 xeapi S 字段 (X25519 + AES-128-GCM)
const decryptXeapiS = (sField, privateKey) => {
	const raw = Buffer.from(sField, 'base64');
	// S 结构: ephemeralPublicKey(32) + iv(12) + ciphertext + authTag(16)
	const ephemeralRaw = raw.subarray(0, 32);
	const iv = raw.subarray(32, 44);
	const authTag = raw.subarray(raw.length - 16);
	const ciphertext = raw.subarray(44, raw.length - 16);
	
	// 构造 ephemeral 公钥对象 (DER SPKI)
	const ephemeralKey = crypto.createPublicKey({
		key: Buffer.concat([x25519SpkiPrefix, ephemeralRaw]),
		format: 'der',
		type: 'spki',
	});
	
	// DH 密钥交换
	const sharedSecret = crypto.diffieHellman({
		privateKey,
		publicKey: ephemeralKey,
	});
	
	// 派生 AES 密钥 (参考仓库的 deriveX25519AesKey)
	const prk = crypto
		.createHmac('sha256', Buffer.alloc(32))
		.update(sharedSecret.length ? sharedSecret : Buffer.alloc(32))
		.digest();
	const aesKey = crypto
		.createHmac('sha256', prk)
		.update(Buffer.concat([ephemeralRaw, Buffer.from([1])]))
		.digest()
		.subarray(0, 16);
	
	// AES-128-GCM 解密
	const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
	decipher.setAuthTag(authTag);
	const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	
	// 解析明文: base64(dynamicKey)|os|sk
	const parts = decrypted.toString().split('|');
	const dynamicKeyBase64 = parts[0];
	return Buffer.from(dynamicKeyBase64, 'base64');
};

// 生成 MITM X25519 密钥对
const generateMitmKeyPair = () => {
	const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
	const raw = Buffer.from(
		publicKey.export({ format: 'der', type: 'spki' })
	).subarray(-32);
	return {
		publicKey: raw.toString('base64'),
		privateKey,
	};
};

// 用 MITM 私钥解密 S 字段，返回明文 (dynamicKey|os|sk)
const parseXeapiS = (sField, privateKey) => {
	const raw = Buffer.from(sField, 'base64');
	const ephemeralRaw = raw.subarray(0, 32);
	const iv = raw.subarray(32, 44);
	const authTag = raw.subarray(raw.length - 16);
	const ciphertext = raw.subarray(44, raw.length - 16);

	const ephemeralKey = crypto.createPublicKey({
		key: Buffer.concat([x25519SpkiPrefix, ephemeralRaw]),
		format: 'der',
		type: 'spki',
	});
	const sharedSecret = crypto.diffieHellman({ privateKey, publicKey: ephemeralKey });
	const prk = crypto
		.createHmac('sha256', Buffer.alloc(32))
		.update(sharedSecret.length ? sharedSecret : Buffer.alloc(32))
		.digest();
	const aesKey = crypto
		.createHmac('sha256', prk)
		.update(Buffer.concat([ephemeralRaw, Buffer.from([1])]))
		.digest()
		.subarray(0, 16);

	const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
	decipher.setAuthTag(authTag);
	const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
	const [dynamicKeyB64, os, sk] = decrypted.toString().split('|');
	return {
		dynamicKey: Buffer.from(dynamicKeyB64, 'base64'),
		os: os || 'android',
		sk: sk || '',
	};
};

// 用服务端真实公钥重加密 S 字段 (MITM 转发)
// 客户端用 MITM 公钥加密 S → 代理用私钥解出 dynamicKey → 用服务端公钥重加密
const reEncryptXeapiS = (sField, serverPublicKeyB64, privateKey) => {
	const parsed = parseXeapiS(sField, privateKey);
	const peerRaw = Buffer.from(serverPublicKeyB64, 'base64');
	const peerKey = crypto.createPublicKey({
		key: Buffer.concat([x25519SpkiPrefix, peerRaw]),
		format: 'der',
		type: 'spki',
	});
	// 生成新的临时密钥对，用私钥做 DH
	const { publicKey, privateKey: ephemPrivateKey } = crypto.generateKeyPairSync('x25519');
	const ephemeralRaw = Buffer.from(
		publicKey.export({ format: 'der', type: 'spki' })
	).subarray(-32);
	const sharedSecret = crypto.diffieHellman({
		privateKey: ephemPrivateKey,
		publicKey: peerKey,
	});
	// 派生 AES 密钥 (与客户端侧 deriveX25519AesKey 相同)
	const prk = crypto
		.createHmac('sha256', Buffer.alloc(32))
		.update(sharedSecret.length ? sharedSecret : Buffer.alloc(32))
		.digest();
	const aesKey = crypto
		.createHmac('sha256', prk)
		.update(Buffer.concat([ephemeralRaw, Buffer.from([1])]))
		.digest()
		.subarray(0, 16);

	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
	const plaintext = Buffer.from(
		`${parsed.dynamicKey.toString('base64')}|${parsed.os}|${parsed.sk}`
	);
	const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	return Buffer.concat([
		ephemeralRaw,
		iv,
		encrypted,
		cipher.getAuthTag(),
	]).toString('base64');
};

// 解密完整的 xeapi 请求 (B + S 字段)
const decryptXeapiRequest = ({ B, S, privateKey }) => {
	// 1. 解密 S 获取动态密钥
	const dynamicKey = decryptXeapiS(S, privateKey);
	
	// 2. 用动态密钥解密 B 的外层 (AES-128-ECB)
	const bRaw = Buffer.from(B, 'base64');
	const midTransformed = decrypt128Ecb(bRaw, dynamicKey);
	
	// 3. 逆变换
	const innerEncrypted = xeapiMidUntransform(midTransformed);
	
	// 4. 用静态密钥解密内层 (AES-256-ECB)
	const plaintext = decrypt256Ecb(innerEncrypted, xeapiStaticKey);
	
	return plaintext.toString();
};

// xeapi/eapi 响应解密: 参考 api-enhanced 的 xeapiResDecrypt
// 1. AES-128-ECB(eapiKey) 解密
// 2. 检查结果是否以 gzip 魔头 (0x1f 0x8b) 开头, 是则解压
// 3. 返回 JSON.parse 后的对象
const eapiResDecrypt = (body) => {
	const decrypted = decrypt128Ecb(body, eapiKey);
	const plaintext =
		decrypted.length > 2 &&
		decrypted[0] === 0x1f &&
		decrypted[1] === 0x8b
			? zlib.gunzipSync(decrypted)
			: decrypted;
	return JSON.parse(plaintext.toString());
};

// 解析 xeapi 请求明文 (buildXeapiPlaintext 的输出)
// 格式: {"contentType":"...","method":"GET","queryString":"...&e_r=true","body":"base64(...)"}
const parseXeapiPlaintext = (decryptedText) => {
	let parsed;
	try {
		parsed = JSON.parse(decryptedText);
	} catch (e) {
		return null; // 不是 JSON, 可能是旧格式
	}
	if (!parsed || typeof parsed !== 'object') return null;
	if (
		!('queryString' in parsed) &&
		!('body' in parsed) &&
		!('method' in parsed)
	) {
		return null; // 不是 xeapi 新格式
	}
	return {
		contentType: parsed.contentType || null,
		method: (parsed.method || 'POST').toUpperCase(),
		queryString: parsed.queryString || '',
		body: parsed.body || null,
	};
};

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
		encrypt: (buffer) => encrypt128Ecb(buffer, xeapiOldKey),
		decrypt: (buffer) => decrypt128Ecb(buffer, xeapiOldKey),
		// 新的完整解密函数 (MITM + X25519 + 双层 AES)
		decryptRequest: decryptXeapiRequest,
		// 解密服务器返回的公钥响应
		decryptResponse: (buffer) => decrypt256Ecb(buffer, xeapiStaticKey),
		// 加密公钥响应 (MITM 替换)
		encryptResponse: (buffer) => encrypt256Ecb(buffer, xeapiStaticKey),
		// xeapi/eapi 响应解密 (AES-128-ECB + gzip 检查)
		eapiResDecrypt,
		// 解析 xeapi 请求明文 (buildXeapiPlaintext 输出)
		parseXeapiPlaintext,
		// MITM 密钥交换
		generateMitmKeyPair,
		parseXeapiS,
		reEncryptXeapiS,
		// 签名
		sign: xeapiSign,
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
	eapiResDecrypt,
	parseXeapiPlaintext,
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