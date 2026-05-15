FROM ubuntu:24.04 AS builder

ARG MONGO_CXX_DRIVER_VERSION=r4.1.4

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-utils \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        git \
        libsasl2-dev \
        libssl-dev \
        libboost-all-dev \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN curl -L -o mongo-cxx-driver.tar.gz \
        "https://github.com/mongodb/mongo-cxx-driver/releases/download/${MONGO_CXX_DRIVER_VERSION}/mongo-cxx-driver-${MONGO_CXX_DRIVER_VERSION}.tar.gz" \
    && tar -xzf mongo-cxx-driver.tar.gz \
    && cmake -S "mongo-cxx-driver-${MONGO_CXX_DRIVER_VERSION}" \
        -B "mongo-cxx-driver-${MONGO_CXX_DRIVER_VERSION}/build" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_CXX_STANDARD=17 \
    && cmake --build "mongo-cxx-driver-${MONGO_CXX_DRIVER_VERSION}/build" --target install -j"$(nproc)"

WORKDIR /app

COPY CMakeLists.txt ./
COPY include ./include
COPY src ./src

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)"

FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl-dev \
        libcurl4 \
        libsasl2-2 \
        libssl3 \
        zlib1g \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /app/build/health-api /app/health-api

ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /app

CMD ["./health-api"]
