CC ?= cc
CFLAGS ?= -O2 -std=c17 -Wall -Wextra
LDLIBS ?=
# Termux 装在 $PREFIX；其它系统默认 /usr/local（make install 才需要 root）
PREFIX ?= $(if $(wildcard /data/data/com.termux),/data/data/com.termux/files/usr,/usr/local)

# TLS 只用于抓 https 站点的 Server/title。有 openssl 头就编进去，没有就跳过 https。
TLS_OK := $(shell printf '#include <openssl/ssl.h>\nint main(void){return 0;}\n' \
	| $(CC) -x c - -lssl -lcrypto -o /dev/null 2>/dev/null && echo yes)
ifeq ($(TLS_OK),yes)
LDLIBS += -lssl -lcrypto
else
CFLAGS += -DHAKU_NO_TLS
$(warning 没有可用的 openssl 开发头，https 指纹将被跳过；Ubuntu 上装一下：sudo apt install libssl-dev)
endif

haku: haku.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS) -lpthread

install: haku
	install -m 755 haku $(PREFIX)/bin/haku

clean:
	rm -f haku

.PHONY: install clean
