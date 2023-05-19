# Build Stage
FROM --platform=linux/amd64 rustlang/rust:nightly as builder

ENV DEBIAN_FRONTEND=noninteractive
## Install build dependencies.
RUN apt-get update 
RUN apt-get install -y cmake clang
RUN cargo install cargo-fuzz

## Add source code to the build stage.
ADD . /Poseidon252/

WORKDIR /Poseidon252/fuzz/

RUN cargo +nightly fuzz build

FROM --platform=linux/amd64 rustlang/rust:nightly

## TODO: Change <Path in Builder Stage>

COPY --from=builder /Poseidon252/fuzz/target/x86_64-unknown-linux-gnu/release/sponge_hash /

COPY --from=builder /Poseidon252/fuzz/target/x86_64-unknown-linux-gnu/release/encrypt /

COPY --from=builder /Poseidon252/fuzz/target/x86_64-unknown-linux-gnu/release/encrypt_decrypt /

COPY --from=builder /Poseidon252/fuzz/target/x86_64-unknown-linux-gnu/release/decrypt_fail /