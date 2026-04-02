CC = gcc
CFLAGS = -Wall -Wextra -O2

TARGET = security_eval_server

.PHONY: all clean local arm64 armv7 run help

all: $(TARGET)

$(TARGET): security_eval_server.c
	$(CC) $(CFLAGS) -o $@ $<

local: $(TARGET)

arm64:
	aarch64-linux-gnu-gcc $(CFLAGS) -o $(TARGET)-arm64 security_eval_server.c

armv7:
	arm-linux-gnueabihf-gcc $(CFLAGS) -o $(TARGET)-armv7 security_eval_server.c

clean:
	rm -f $(TARGET) $(TARGET)-arm64 $(TARGET)-armv7

run: $(TARGET)
	sudo ./$(TARGET)

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  local   - 本地编译 (x86_64)"
	@echo "  arm64   - 交叉编译 ARM64"
	@echo "  armv7   - 交叉编译 ARM32"
	@echo "  clean   - 清理"
	@echo "  run     - 运行 (需要 root)"
	@echo "  help    - 帮助"