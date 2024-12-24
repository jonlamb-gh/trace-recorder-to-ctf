FROM ubuntu:22.04

LABEL org.opencontainers.image.source="https://github.com/jonlamb-gh/trace-recorder-to-ctf"
LABEL org.opencontainers.image.description="Docker image for trace-recorder-to-ctf"
LABEL org.opencontainers.image.licenses=MIT

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y && apt-get install --no-install-recommends --assume-yes  \
    patchelf lintian adduser help2man gzip \
    cmake make gcc g++ libusb-1.0-0-dev stunnel \
    curl build-essential protobuf-compiler libssl-dev \
    python3 python3-pip python3-venv \
    libglib2.0-dev pkg-config libtool flex bison autoconf ca-certificates automake

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --profile minimal -c rustfmt -c clippy
ENV PATH="/root/.cargo/bin:${PATH}"

RUN mkdir -p /trace-recorder-to-ctf
COPY assets/ /trace-recorder-to-ctf/assets/
COPY Cargo.lock /trace-recorder-to-ctf/
COPY Cargo.toml /trace-recorder-to-ctf/
COPY LICENSE-MIT /trace-recorder-to-ctf/
COPY macros/ /trace-recorder-to-ctf/macros/
COPY README.md /trace-recorder-to-ctf/
COPY src/ /trace-recorder-to-ctf/src/

RUN cd /trace-recorder-to-ctf && ls -l && cargo install --path .

ENTRYPOINT ["/root/.cargo/bin/trace-recorder-to-ctf"]
