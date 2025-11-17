# NetForge - Custom TCP/IP Stack Makefile
# Developed by Yx0R

CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -I./src -D_GNU_SOURCE
TARGET = netforge
SOURCES = src/main.c src/ipv4.c src/icmp.c src/tcp.c src/udp.c src/ethernet.c

# Colors for pretty output
GREEN = \033[0;32m
BLUE = \033[0;34m
RED = \033[0;31m
NC = \033[0m

.PHONY: all build install clean capabilities debug help

all: build

build:
	@echo "$(BLUE)🛠️  Building NetForge...$(NC)"
	@$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)
	@echo "$(GREEN)✅ Build successful!$(NC)"

install: build
	@echo "$(BLUE)📦 Installing NetForge...$(NC)"
	@sudo cp $(TARGET) /usr/local/bin/
	@echo "$(GREEN)✅ Installed to /usr/local/bin/netforge$(NC)"

capabilities: build
	@echo "$(BLUE)🔧 Setting capabilities...$(NC)"
	@sudo setcap cap_net_raw+ep $(TARGET)
	@echo "$(GREEN)✅ Raw socket capabilities enabled$(NC)"

debug:
	@echo "$(BLUE)🐛 Building with debug symbols...$(NC)"
	@$(CC) $(CFLAGS) -g -o $(TARGET) $(SOURCES)
	@echo "$(GREEN)✅ Debug build complete$(NC)"

clean:
	@echo "$(BLUE)🧹 Cleaning build...$(NC)"
	@rm -f $(TARGET)
	@echo "$(GREEN)✅ Clean complete$(NC)"

help:
	@echo "NetForge Build System"
	@echo "====================="
	@echo "make build       - Build the application"
	@echo "make install     - Install to system"
	@echo "make capabilities - Enable raw socket permissions"
	@echo "make debug       - Build with debug symbols"
	@echo "make clean       - Remove built files"
	@echo "make help        - Show this help"

# Default target
default: build
