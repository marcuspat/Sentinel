# ââ Stage 1: build ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the release binary in one layer so CI cache is maximally effective.
RUN cargo build --release --bin sentinel

# ââ Stage 2: runtime âââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sentinel /usr/local/bin/sentinel

# Operators override these at runtime â never bake keys into the image.
ENV ANTHROPIC_API_KEY="" \
    OPENAI_API_KEY="" \
    RUST_LOG="info"

ENTRYPOINT ["sentinel"]
CMD ["--help"]
