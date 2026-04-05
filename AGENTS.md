# AGENTS.md

## Setup

```bash
pnpm install
cp .env.example .env
node src/server/generate-cert.js  # Generate HTTPS certs for proxy
```

## Run

```bash
pnpm start
```

- Frontend: http://localhost:3000
- Proxy server: http://localhost:9000

## Test

Jest tests exist in `src/server/request.test.js`. No test script in package.json - run with:
```bash
npx jest
```

## Project Structure

- `src/index.js` - Main entry, starts both servers
- `src/server/` - Proxy server (app.js, server.js, hook.js)
- `src/client/` - Frontend static files

## Important Notes

- Requires pnpm (specified in `packageManager` field)
- HTTPS proxy needs `server.crt`/`server.key` generated via `generate-cert.js`
- First-time: must trust the self-signed cert in Netease Music client
