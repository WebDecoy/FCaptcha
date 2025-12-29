FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install --production

COPY server.js .

EXPOSE 3000

ENV PORT=3000

CMD ["node", "server.js"]
