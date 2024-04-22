# Build Gtos in a stock Go builder container
FROM golang:1.22.2-bookworm as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git

ADD . /tos
RUN cd /tos && make gtos

# Pull Gtos into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /tos/build/bin/gtos /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["gtos"]
