FROM node:8.5.0
MAINTAINER Masresha Tsegaye <masresha.tsegaye@gmail.com>
WORKDIR /app
COPY package.json /app
RUN npm install
COPY . /app
EXPOSE 8880
ENTRYPOINT ["node", "app.js"]
