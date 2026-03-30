BINARY_NAME := "nutmix_remote_signer"
INSTALL_DIR := "/usr/local/bin"
SERVICE_DIR := "/etc/systemd/system"
SERVICE_NAME := "nutmix_remote_signer.service"

default: build

# Build the signer binary
build: proto templ
  @echo "Building {{BINARY_NAME}}..."
  @go build -o {{BINARY_NAME}} .

# Run protobuf code generation for gRPC
proto: 
  protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional gen/signer.proto

# Run templ code generation
templ:
  go run github.com/a-h/templ/cmd/templ@v0.3.943 generate

# Store seedphrase in libsecret
seed:
  @echo "NOTE: this command prompts for the seedphrase as a password"
  @secret-tool store --label="nutvault-seed" label nutvault-seed

# Run the signer in development mode
dev: proto templ
  go run .

# Run tests
test:
  go test ./...

# Build and run the signer
run: build
  ./{{BINARY_NAME}}

# Install binary and systemd service
install: build
  @echo "Installing {{BINARY_NAME}} to {{INSTALL_DIR}}..."
  @sudo cp {{BINARY_NAME}} {{INSTALL_DIR}}
  @echo "Creating systemd service file..."
  @sudo cp nutmix_remote_signer.service {{SERVICE_DIR}}/{{SERVICE_NAME}}
  @echo "Reloading systemd daemon..."
  @sudo systemctl daemon-reload
  @echo "Enabling {{SERVICE_NAME}}..."
  @sudo systemctl enable {{SERVICE_NAME}}
  @echo "Starting {{SERVICE_NAME}}..."
  @sudo systemctl start {{SERVICE_NAME}}
  @echo "Installation complete."

# Uninstall binary and systemd service
uninstall:
  @echo "Stopping {{SERVICE_NAME}}..."
  @sudo systemctl stop {{SERVICE_NAME}}
  @echo "Disabling {{SERVICE_NAME}}..."
  @sudo systemctl disable {{SERVICE_NAME}}
  @echo "Removing systemd service file..."
  @sudo rm {{SERVICE_DIR}}/{{SERVICE_NAME}}
  @echo "Reloading systemd daemon..."
  @sudo systemctl daemon-reload
  @echo "Removing {{BINARY_NAME}} from {{INSTALL_DIR}}..."
  @sudo rm {{INSTALL_DIR}}/{{BINARY_NAME}}
  @echo "Uninstallation complete."

# Remove built binary
clean:
  @echo "Cleaning up..."
  @rm -f {{BINARY_NAME}}
