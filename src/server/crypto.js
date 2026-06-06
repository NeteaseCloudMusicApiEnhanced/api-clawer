'use strict';

const crypto = require('crypto');
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