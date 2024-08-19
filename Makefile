.PHONY: sender receiver clean tap0 udp_server server

define build_and_run
	@echo "========== Building $(1) =========="
	@if cargo build --release --example $(1); then \
		echo "Build successful"; \
	else \
		echo "Build failed"; \
		exit 1; \
	fi
	@echo "Copying $(1) binary to current directory"
	@cp ./target/release/examples/$(1) $(2)
	@echo "========== Build Done =========="
	@echo "Starting $(2) with TAP device $(3)"
	@sudo ./$(2) --tap $(3)
	@rm -rf $(2)
endef

# sender 目标
sender:
	@rm -rf sender
	$(call build_and_run,bridge-sender,sender,tap1)

# receiver 目标
receiver:
	@rm -rf receiver
	$(call build_and_run,bridge-receiver,receiver,tap2)

network:
	@rm -rf network-bridge
	@cargo build --release --example network-bridge 
	@sudo ./target/release/examples/network-bridge

clean:
	@echo "Cleaning"
	@rm -rf sender receiver udp_server server
	@echo "Clean Done"

tap0:
	@echo "========== Starting smoltcp UDP test =========="
	@echo "Sending 'Hello, World!' to 192.168.69.1:6969"
	@echo "Hello, World\!" | nc -u 192.168.69.1 6969

server:
	@rm -rf server
	$(call build_and_run,server,server,tap0)

udp_server:
	@rm -rf udp_server
	@echo "========== Building udp_server =========="
	@if cargo build --release --example udp_server; then \
		echo "Build successful"; \
	else \
		echo "Build failed"; \
		exit 1; \
	fi
	@echo "Copying udp_server binary to current directory"
	@cp ./target/release/examples/udp_server udp_server
	@echo "========== Build Done =========="
	@echo "Starting udp_server with TAP device tap0"
	@sudo RUST_BACKTRACE=full ./udp_server
# @rm -rf udp_server
	
# $(call build_and_run,udp_server,udp_server,tap0)