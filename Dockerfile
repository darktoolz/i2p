# syntax=docker/dockerfile:1

FROM alpine:latest AS base
ARG SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
RUN apk add --no-cache ca-certificates build-base make gcc autoconf libsodium-dev git curl \
			boost boost-dev boost-chrono boost-filesystem boost-system boost-thread \
			boost-date_time boost-program_options libssl3 openssl3-dev nss zlib-dev openssh \
			inetutils-telnet

ADD https://github.com/PurpleI2P/i2pd-tools.git /root/i2p_keytool
WORKDIR /root/i2p_keytool
RUN make libi2pd.a

FROM base AS builder
ARG SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
WORKDIR /root/i2p_keytool
RUN \
	--mount=type=bind,source=Base.patch,target=Base.patch \
	--mount=type=bind,source=keygen.cpp,target=keygen.cpp \
		patch -p0 < Base.patch && \
		tail -n +2 keygen.cpp > keyinfo.cpp && \
  	make keygen keyinfo && \
		cp keygen keyinfo /usr/bin/

FROM alpine:latest AS build
ARG SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
RUN apk add --no-cache curl i2pd bash libssl3 openssl3-dev nss zlib-dev make

COPY --from=builder /usr/bin/keygen /usr/bin/
COPY --from=builder /usr/bin/keyinfo /usr/bin/
COPY --chmod=777 docker-entrypoint.sh /
COPY test.mk /

FROM scratch
ARG SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
COPY --from=build / /

EXPOSE 7070 4444 4447
HEALTHCHECK --start-period=30s --start-interval=3s --retries=10 --timeout=1s --interval=30s \
  CMD test $(curl --noproxy "localhost" -s localhost:7070 | grep success | grep -oE '[0-9]+' || echo -n 0) -gt 10
ENTRYPOINT ["/docker-entrypoint.sh"]
