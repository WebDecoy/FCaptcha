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

# Every module server.py imports. Copying the entrypoint alone leaves the image
# unable to start, and nothing in a Dockerfile review makes that visible — keep
# this list in step with server.py's imports.
COPY server-python/server.py \
     server-python/detection.py \
     server-python/clientip.py \
     server-python/sitekeys.py \
     server-python/inputforensics.py \
     ./

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
