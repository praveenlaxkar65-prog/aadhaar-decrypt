FROM node:20-slim

RUN apt-get update -y && apt-get install -y qpdf && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
