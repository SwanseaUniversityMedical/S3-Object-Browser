ARG NODE_VERSION=20

FROM node:${NODE_VERSION}-bullseye AS ui

WORKDIR /src/web-app

# Copy package files and install dependencies first  
COPY web-app/package.json web-app/.yarnrc.yml ./
RUN corepack enable && yarn install

# Copy configuration files
COPY web-app/tsconfig.json web-app/config-overrides.js ./

# Copy source files
COPY web-app/public ./public
COPY web-app/src ./src

RUN npx update-browserslist-db@latest && yarn build

FROM golang:1.24.4 AS build

ARG BUILD_VERSION
ARG BUILD_TIME

RUN apt-get update -y \
	&& apt-get install -y ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . ./
COPY --from=ui /src/web-app/build /src/web-app/build

ENV CGO_ENABLED=0

RUN go build -trimpath --tags=kqueue --ldflags "-s -w" -o console ./cmd/console

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.5

EXPOSE 9090

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/console /console

ENTRYPOINT ["/console"]