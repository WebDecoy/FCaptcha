# Python/FastAPI implementation.
#
# Build from the REPOSITORY ROOT, not from this directory — the image needs
# client/fcaptcha.js, which lives outside this folder:
#
#   docker build -f server-python/Dockerfile -t fcaptcha-python .
#
# The layout inside the image mirrors the repository on purpose. server.py
# resolves the widget at ../client/fcaptcha.js relative to its own directory, so
# keeping server-python/ and client/ as siblings means it works with no
# configuration, exactly as it does from a checkout.
FROM python:3.12-slim

WORKDIR /app/server-python

COPY server-python/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# All of it, rather than a list of modules to keep in step with server.py's
# imports. That list was the defect: a module added to the server and not to the
# Dockerfile produces an image that crashes on startup, which no Dockerfile
# review makes visible and which the previous instruction here did not prevent.
COPY server-python/*.py ./
RUN rm -f test_*.py

# Sibling of server-python/, so ../client/fcaptcha.js resolves.
COPY client/fcaptcha.js /app/client/fcaptcha.js

EXPOSE 3000
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:3000/health').status==200 else 1)" || exit 1

# `python server.py` rather than a bare uvicorn invocation: the __main__ block
# starts uvicorn with proxy_headers=False, which FCaptcha requires so that
# TRUSTED_PROXIES is the only thing resolving a client address.
CMD ["python", "server.py"]
