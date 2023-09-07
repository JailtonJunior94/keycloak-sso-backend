FROM golang:1.21 AS builder

WORKDIR /go/src/server
RUN apt-get update

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN make build

FROM alpine:3.16
WORKDIR /app/

COPY --from=builder /go/src/server/bin/server .
COPY --from=builder /go/src/server/cmd/.env .

EXPOSE 80
EXPOSE 443
CMD ["./server"]