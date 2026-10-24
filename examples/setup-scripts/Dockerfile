FROM node
WORKDIR /app
ENV API_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789
COPY . .
RUN curl -sL https://deb.example.com/setup | bash - && npm install expresss
EXPOSE 3000 22
CMD ["node", "server.js"]
