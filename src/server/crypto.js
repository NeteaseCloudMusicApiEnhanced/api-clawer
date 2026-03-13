'use strict';

const crypto = require('crypto');
const parse = require('url').parse;
const bodyify = require('querystring').stringify;

const eapiKey = 'e82ckenh8dichen8';
const linuxapiKey = 'rFgB&h#%2?^eDg:Q';

const decrypt = (buffer, key) => {
	const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
	return Buffer.concat([decipher.update(buffer), decipher.final()]);
};

const encrypt = (buffer, key) => {
	const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
	return Buffer.concat([cipher.update(buffer), cipher.final()]);
};

module.exports = {
	eapi: {
		encrypt: (buffer) => encrypt(buffer, eapiKey),
		decrypt: (buffer) => decrypt(buffer, eapiKey),
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
		encrypt: (buffer) => encrypt(buffer, linuxapiKey),
		decrypt: (buffer) => decrypt(buffer, linuxapiKey),
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