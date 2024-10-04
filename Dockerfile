# specify the how container works
FROM rust:1.81

WORKDIR /zk-grpc

COPY . .
RUN apt update
# RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# RUN apt-get install protobuf-compiler
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends --assume-yes \
    protobuf-compiler
# The rest of your Dockerfile as above
RUN cargo build --release --bin server --bin client
