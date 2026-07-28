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

# All of it, rather than a list of modules to keep in step with server.js's
# requires. That list was the defect: a module added to the server and not to the
# Dockerfile produces an image that crashes on startup, which no Dockerfile
# review makes visible and which the previous instruction here did not prevent.
COPY server-node/*.js ./
RUN rm -f *.test.js

# Sibling of server-node/, so ../client/fcaptcha.js resolves.
COPY client/fcaptcha.js /app/client/fcaptcha.js

EXPOSE 3000
ENV PORT=3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
