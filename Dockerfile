FROM node:20.20.2-alpine3.23

WORKDIR /app

COPY package.json ./
COPY server.js ./

EXPOSE 3000

CMD ["node", "server.js"]
