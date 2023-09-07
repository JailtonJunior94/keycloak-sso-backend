build:
	@echo "Compiling API..."
	@CGO_ENABLED=0 go build -ldflags="-w -s" -o ./bin/server ./cmd/server.go