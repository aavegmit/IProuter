TARGETS=router
all: ${TARGETS}

router: main.o sniffer.o
	g++ -o router main.o sniffer.o -D_REETRANT -lpthread -lpcap

main.o: main.cc
	g++ -c -g main.cc  -D_REETRANT -lpthread -lpcap

sniffer.o: sniffer.cc
	g++ -c -g sniffer.cc  -D_REETRANT -lpthread -lpcap

clean:
	rm -rf *.o router

