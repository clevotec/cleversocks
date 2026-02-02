FROM --platform=$BUILDPLATFORM alpine AS selector
ARG TARGETPLATFORM
COPY binaries/ /binaries/
RUN set -e; \
    case "$TARGETPLATFORM" in \
      linux/amd64)   bin=cleversocks-linux-amd64 ;; \
      linux/arm64*)  bin=cleversocks-linux-arm64 ;; \
      linux/arm/v7)  bin=cleversocks-linux-armv7 ;; \
      linux/386)     bin=cleversocks-linux-i686 ;; \
      *) echo "Unsupported platform: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac; \
    cp "/binaries/$bin" /cleversocks; \
    chmod +x /cleversocks

FROM scratch
LABEL org.opencontainers.image.licenses=MIT
COPY --from=selector /cleversocks /
ENTRYPOINT ["/cleversocks"]
