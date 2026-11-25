import { createServer } from 'node:http';
import { createRequestListener } from 'remix/node-fetch-server';
import { createContactRouter } from './server.mjs';

const secret = process.env.FCAPTCHA_VERIFY_SECRET;
if (!secret) throw new Error('Set FCAPTCHA_VERIFY_SECRET before starting the demo.');

const hostname = '127.0.0.1';
const port = Number(process.env.PORT || 8796);
const appOrigin = 'http://' + hostname + ':' + port;
const verifierOrigin = process.env.FCAPTCHA_ORIGIN || 'http://127.0.0.1:8797';
const router = createContactRouter({ appOrigin, verifierOrigin, secret });

createServer(createRequestListener(router.fetch)).listen(port, hostname, () => console.log(appOrigin));
