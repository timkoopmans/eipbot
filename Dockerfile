FROM rust:1.67.1 as builder
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=builder ./target/release/eipbot ./target/release/eipbot
CMD ["/target/release/eipbot"]