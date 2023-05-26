FROM golang:1.20-alpine3.18 AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build 

FROM scratch

COPY --from=builder /app/syslog_ng_exporter /app/

EXPOSE 9577

ENTRYPOINT ["/app/syslog_ng_exporter"]
