const parse = require('url').parse;
const crypto = require('./crypto');
const request = require('./request');
const querystring = require('querystring');
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
];

hook.request.before = (ctx) => {
	const { req } = ctx;
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
	if (
		[url.hostname, req.headers.host].some((host) =>
			isHost(host, 'music.163.com')
		)
	)
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
					ctx.netease = netease;
					console.log(netease.path, netease.param) // 这里输出了网易云音乐的抓包数据, 重点看这里
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
		ctx.netease = {
			web: true,
			path: url.path
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
	if (
		req.headers.host === 'tyst.migu.cn' &&
		proxyRes.headers['content-range'] &&
		proxyRes.statusCode === 200
	)
		proxyRes.statusCode = 206;
	if (
		netease &&
		hook.target.path.has(netease.path) &&
		proxyRes.statusCode === 200
	) {
		return request
			.read(proxyRes, true)
			.then((buffer) =>
				buffer.length ? (proxyRes.body = buffer) : Promise.reject()
			)
			.then((buffer) => {
				const patch = (string) =>
					string.replace(
						/([^\\]"\s*:\s*)(\d{16,})(\s*[}|,])/g,
						'$1"$2L"$3'
					); // for js precision

				if (netease.e_r) {
					// eapi's e_r is true, needs to be encrypted
					netease.jsonBody = JSON.parse(
						patch(crypto.eapi.decrypt(buffer).toString())
					);
				} else {
					netease.jsonBody = JSON.parse(patch(buffer.toString()));
				}

				// Send data to frontend
				const dataToSend = {
					timestamp: new Date().toISOString(),
					path: netease.path,
					param: netease.param,
					response: netease.jsonBody
				};
				axios.post(`http://localhost:${process.env.PORT || 3000}/api/capture`, dataToSend)
					.catch(err => logger.error('Failed to send data to frontend:', err));
			})
			.catch(
				(error) =>
					error &&
					logger.error(
						error,
						`A error occurred in hook.request.after when hooking ${req.url}.`
					)
			);
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
};

hook.connect.before = (ctx) => {
	const { req } = ctx;
	const url = parse('https://' + req.url);
	if (
		[url.hostname, req.headers.host].some((host) =>
			hook.target.host.has(host)
		)
	) {
		if (parseInt(url.port) === 80) {
			req.url = `${global.address || 'localhost'}:${global.port[0]}`;
			req.local = true;
		} else if (global.port[1]) {
			req.url = `${global.address || 'localhost'}:${global.port[1]}`;
			req.local = true;
		} else {
			ctx.decision = 'blank';
		}
	} else if (url.href.includes(global.endpoint)) ctx.decision = 'proxy';
};

hook.negotiate.before = (ctx) => {
	const { req, socket, decision } = ctx;
	const url = parse('https://' + req.url);
	const target = hook.target.host;
	if (req.local || decision) return;
	if (target.has(socket.sni) && !target.has(url.hostname)) {
		target.add(url.hostname);
		ctx.decision = 'blank';
	}
};

module.exports = hook;