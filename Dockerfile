FROM jhleeeme/ubuntu:20.04
LABEL maintainer="JHLeeeMe" \
      description="C++ dev-container"

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y --no-install-recommends install \
        build-essential \
        cmake \
        net-tools \
        tree \
        git
