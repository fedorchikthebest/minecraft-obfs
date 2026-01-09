all:
	clang ./main.c ./evenst/callbacks.c -lev -lssl -lcrypto -o build/minecraft-obfs
