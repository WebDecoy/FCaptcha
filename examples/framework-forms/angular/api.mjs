import express from 'express';
import { contactHandler } from '../shared/contact.mjs';
export function createApi(config) {
  const app = express();
  app.use(express.raw({ type: '*/*', limit: '16kb' }));
  const handler = contactHandler(config);
  app.post('/api/contact', async (req, res, next) => {
    try {
      const request = new Request(config.origin + '/api/contact', {
        method: 'POST', headers: { origin: req.get('origin') || '', 'content-type': req.get('content-type') || '' },
        body: req.body instanceof Buffer ? req.body : ''
      });
      const result = await handler(request);
      res.status(result.status).set(Object.fromEntries(result.headers)).send(await result.text());
    } catch (error) { next(error); }
  });
  app.use((error, req, res, next) => res.status(error.status === 413 ? 413 : 500).json({ error: 'request_failed' }));
  return app;
}
