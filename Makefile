all:
	gcc -lpcap -I./lib sniffer.c -o sniffer
