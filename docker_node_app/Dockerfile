# use a node base image
FROM node:latest

# set maintainer
LABEL maintainer "kunal.pagariya@gmail.com"

WORKDIR /app

# set a health check
HEALTHCHECK --interval=10s \
            --timeout=10s \
            CMD curl -f http://127.0.0.1:8000 || exit 1

# tell docker what port to expose
EXPOSE 8000

COPY . . 
RUN npm install
CMD ["npm","start"]