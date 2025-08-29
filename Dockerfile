FROM clux/muslrust:1.89.0-stable-2025-08-27 AS builder

WORKDIR /opt/wenceslas
COPY . .
RUN cargo build --release --locked
RUN cp target/$CARGO_BUILD_TARGET/release/wenceslas /wenceslas

FROM gcr.io/distroless/static
COPY --from=builder /wenceslas /opt/wenceslas/bin/wenceslas
USER 8675309:8675309
ENTRYPOINT ["/opt/wenceslas/bin/wenceslas"]
