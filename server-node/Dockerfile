# Node.js implementation.
#
# Build from the REPOSITORY ROOT, not from this directory — the image needs
# client/fcaptcha.js, which lives outside this folder:
#
#   docker build -f server-node/Dockerfile -t fcaptcha-node .
#
# The layout inside the image mirrors the repository on purpose. server.js
# resolves the widget at ../client/fcaptcha.js relative to its own directory, so
# keeping server-node/ and client/ as siblings means it works with no
# configuration, exactly as it does from a checkout.
FROM node:20-alpine

WORKDIR /app/server-node

COPY server-node/package.json server-node/package-lock.json* ./
RUN npm install --omit=dev

# Every module server.js requires. Copying the entrypoint alone leaves the image
# unable to start, and nothing in a Dockerfile review makes that visible — keep
# this list in step with server.js's requires.
COPY server-node/server.js \
     server-node/detection.js \
     server-node/clientip.js \
     server-node/limits.js \
     server-node/webbotauth.js \
     server-node/inputforensics.js \
     ./

# Sibling of server-node/, so ../client/fcaptcha.js resolves.
COPY client/fcaptcha.js /app/client/fcaptcha.js

EXPOSE 3000
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
