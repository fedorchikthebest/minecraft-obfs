all:
	clang ./main.c ./events/callbacks.c -lev -lssl -lcrypto -o build/minecraft-obfs
