ccarm=mips-openwrt-linux-g++
all:
	mkdir -p bin
	g++ forward.cpp -o bin/forward -static
	${ccarm} forward.cpp -o bin/forwardarm   -static -lgcc_eh
#g++ forward.cpp aes.c -o forward -static
#	${ccarm} forward.cpp aes.c  -o forwardarm   -static -lgcc_eh
