#!/bin/sh

docker run \
    --rm \
    -it \
    -e TZ=Asia/Seoul \
    -v common-volume:/common-volume \
    -v $(pwd):/app \
    --net=host \
    --cap-add=NET_ADMIN \
    --name BPFocket \
    jhleeeme/cpp:dev-alpine \
    bin/bash
