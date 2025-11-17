CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -I./src
TARGET = mytcpip
SOURCES = src/main.c src/ipv4.c src/icmp.c src/tcp.c src/udp.c src/ethernet.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

run: $(TARGET)
	sudo ./$(TARGET)

debug: $(TARGET)
	sudo gdb ./$(TARGET)

clean:
	rm -f $(TARGET)

# Enable raw socket capabilities
capabilities: $(TARGET)
	sudo setcap cap_net_raw+ep $(TARGET)

# Install (copy to system)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

.PHONY: all run debug clean capabilities install
