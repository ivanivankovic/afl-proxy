all:	afl-proxy

afl-proxy:	afl-proxy.c
	$(CC) -I../../include -o afl-proxy afl-proxy.c -ljson-c

clean:
	rm -f afl-proxy *~ core
