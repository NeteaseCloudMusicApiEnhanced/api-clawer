const packageJson = require('../../package.json');
const config = require('./cli.js')
	.program({
		name: packageJson.name.replace(/@.+\//, ''),
		version: packageJson.version,
	})
	.option(['-v', '--version'], { action: 'version' })
	.option(['-p', '--port'], {
		metavar: 'http[:https]',
		help: 'specify server port',
	})
	.option(['-a', '--address'], {
		metavar: 'address',
		help: 'specify server host',
	})
	.option(['-h', '--help'], { action: 'help' })
	.parse(process.argv);

require('dotenv').config();

global.address = config.address;
config.port = (config.port || process.env.HOOK_PORT || '9000')
	.split(':')
	.map((string) => parseInt(string));
const invalid = (value) => isNaN(value) || value < 1 || value > 65535;
if (config.port.some(invalid)) {
	console.log('Port must be a number higher than 0 and lower than 65535.');
	process.exit(1);
}

// 确保 PORT 环境变量可用，供 hook.js 发送数据使用
if (!process.env.PORT) {
	process.env.PORT = process.env.PORT || '3000';
}

const { logScope } = require('./logger');
const parse = require('url').parse;
const hook = require('./hook');
const server = require('./server');
const logger = logScope('app');
const target = Array.from(hook.target.host);

global.port = config.port;
global.proxy = null;
global.hosts = {};
global.endpoint = 'https://music.163.com';

server.whitelist = [
	'://[\\w.]*music\\.126\\.net',
	'://[\\w.]*vod\\.126\\.net',
	'://acstatic-dun.126.net',
	'://[\\w.]*\\.netease.com',
	'://[\\w.]*\\.163yun.com',
];

if (config.endpoint) server.whitelist.push(escape(config.endpoint));

const dns = (host) =>
	new Promise((resolve, reject) =>
		require('dns').lookup(host, { all: true }, (error, records) =>
			error
				? reject(error)
				: resolve(records.map((record) => record.address))
		)
	);

Promise.all(target.map(dns))
	.then((result) => {
		const { host } = hook.target;
		result.forEach((array) => array.forEach(host.add, host));
		server.whitelist = server.whitelist.concat(
			Array.from(host).map(escape)
		);
		const log = (type) =>
			logger.info(
				`${['HTTP', 'HTTPS'][type]} Server running @ http://${
					address || '0.0.0.0'
				}:${port[type]}`
			);
		if (port[0])
			server.http
				.listen(port[0], address)
				.once('listening', () => log(0));
		if (port[1])
			server.https
				.listen(port[1], address)
				.once('listening', () => log(1));
	})
	.catch((error) => {
		console.log(error);
		process.exit(1);
	});