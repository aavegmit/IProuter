TARGETS=router
all: ${TARGETS}

router: main.o sniffer.o parse_packet.o arp.o routingTable.o
	g++ -o router main.o sniffer.o parse_packet.o arp.o routingTable.o -D_REETRANT -lpthread -lpcap

main.o: main.cc
	g++ -c -g main.cc  -D_REETRANT -lpthread -lpcap

sniffer.o: sniffer.cc
	g++ -c -g sniffer.cc  -D_REETRANT -lpthread -lpcap

parse_packet.o: parse_packet.cc
	g++ -c -g parse_packet.cc  -D_REETRANT -lpthread -lpcap

arp.o: arp.cc
	g++ -c -g arp.cc  -D_REETRANT -lpthread -lpcap

routingTable.o: routingTable.cc
	g++ -c -g routingTable.cc  -D_REETRANT -lpthread -lpcap

clean:
	rm -rf *.o router
