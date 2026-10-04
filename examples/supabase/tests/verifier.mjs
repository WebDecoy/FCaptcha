// The parent provides fresh test-only secrets, never production credentials.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { app } = require('../../../server-node/server.js');
const server = app.listen(0, '127.0.0.1', () => {
  console.log(`TEST_PORT=${server.address().port}`);
});
process.stdin.resume();
process.stdin.on('end', () => {
  server.closeAllConnections();
  server.close();
});
