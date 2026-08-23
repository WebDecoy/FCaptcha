import asyncio
import unittest

from server import MAX_REQUEST_BODY_BYTES, RequestBodyLimitMiddleware


class RequestBodyLimitTests(unittest.TestCase):
    def _run(self, body: bytes, content_length=True):
        called = False
        sent = []

        async def downstream(scope, receive, send):
            nonlocal called
            called = True
            message = await receive()
            self.assertEqual(message["body"], body)

        headers = []
        if content_length:
            headers.append((b"content-length", str(len(body)).encode()))
        scope = {"type": "http", "headers": headers}
        messages = iter([{"type": "http.request", "body": body, "more_body": False}])

        async def receive():
            return next(messages)

        async def send(message):
            sent.append(message)

        asyncio.run(RequestBodyLimitMiddleware(downstream)(scope, receive, send))
        return called, sent

    def test_rejects_declared_oversized_body(self):
        called, sent = self._run(b"x", content_length=False)
        self.assertTrue(called)
        self.assertEqual(sent, [])

        async def run_declared():
            called = False
            sent = []

            async def downstream(scope, receive, send):
                nonlocal called
                called = True

            async def receive():
                raise AssertionError("body should not be read")

            async def send(message):
                sent.append(message)

            scope = {"type": "http", "headers": [(b"content-length", str(MAX_REQUEST_BODY_BYTES + 1).encode())]}
            await RequestBodyLimitMiddleware(downstream)(scope, receive, send)
            return called, sent

        called, sent = asyncio.run(run_declared())
        self.assertFalse(called)
        self.assertEqual(sent[0]["status"], 413)

    def test_rejects_chunked_oversized_body(self):
        called, sent = self._run(b"x" * (MAX_REQUEST_BODY_BYTES + 1), content_length=False)
        self.assertFalse(called)
        self.assertEqual(sent[0]["status"], 413)

    def test_allows_small_body(self):
        called, sent = self._run(b"{}")
        self.assertTrue(called)
        self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
