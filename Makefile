
# Makefile for nutmix_remote_signer

BINARY_NAME=nutmix_remote_signer
INSTALL_DIR=/usr/local/bin
SERVICE_DIR=/etc/systemd/system
SERVICE_NAME=nutmix_remote_signer.service

.PHONY: all build install uninstall clean

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(BINARY_NAME) main.go

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@sudo cp $(BINARY_NAME) $(INSTALL_DIR)
	@echo "Creating systemd service file..."
	@sudo cp nutmix_remote_signer.service $(SERVICE_DIR)/$(SERVICE_NAME)
	@echo "Reloading systemd daemon..."
	@sudo systemctl daemon-reload
	@echo "Enabling $(SERVICE_NAME)..."
	@sudo systemctl enable $(SERVICE_NAME)
	@echo "Starting $(SERVICE_NAME)..."
	@sudo systemctl start $(SERVICE_NAME)
	@echo "Installation complete."

uninstall:
	@echo "Stopping $(SERVICE_NAME)..."
	@sudo systemctl stop $(SERVICE_NAME)
	@echo "Disabling $(SERVICE_NAME)..."
	@sudo systemctl disable $(SERVICE_NAME)
	@echo "Removing systemd service file..."
	@sudo rm $(SERVICE_DIR)/$(SERVICE_NAME)
	@echo "Reloading systemd daemon..."
	@sudo systemctl daemon-reload
	@echo "Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	@sudo rm $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstallation complete."

clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME)

