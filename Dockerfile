FROM golang:1.26-trixie AS build
WORKDIR /src
# go.sum may not be present yet; go mod download writes it.
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
ARG VERSION=(devel)
RUN CGO_ENABLED=0 go build \
	-ldflags "-s -w -X github.com/lesomnus/smb-exporter/cmd/version.version=${VERSION}" \
	-o /out/smb-exporter .

# iproute2 carries `ss`, which is what reads the kernel's per-socket byte
# counters, and samba-common-bin carries `smbstatus`, which is the only thing
# that maps a client address to an account. Both are the same tools an operator
# would run by hand.
FROM debian:trixie-slim
RUN apt-get update \
	&& apt-get install -y --no-install-recommends iproute2 samba-common-bin \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /out/smb-exporter /usr/local/bin/smb-exporter
ENTRYPOINT ["smb-exporter"]
