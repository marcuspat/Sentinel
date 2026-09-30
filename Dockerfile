# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM rust:1.86-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the release binary in one layer so CI cache is maximally effective.
RUN cargo build --release --bin sentinel

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sentinel /usr/local/bin/sentinel

# Operators override these at runtime — never bake keys into the image.
ENV ANTHROPIC_API_KEY="" \
    OPENAI_API_KEY="" \
    RUST_LOG="info"

ENTRYPOINT ["sentinel"]
CMD ["--help"]
