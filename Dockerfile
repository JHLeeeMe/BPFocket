FROM alpine:latest
LABEL maintainer="JHLeeeMe" \
      description="C++ dev-container"

RUN apk update && \
    apk upgrade

RUN apk add --no-cache \
        build-base \
        linux-headers \
        gdb \
        cmake \
        bash \
        net-tools \
        git \
        tree
