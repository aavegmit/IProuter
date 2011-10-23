TARGETS=router
all: router

router: main.o sniffer.o parse_packet.o arp.o routingTable.o writePacket.o icmp.o
	g++ -o router main.o sniffer.o parse_packet.o arp.o routingTable.o writePacket.o icmp.o -D_REETRANT -lpthread -lpcap

local: localhost_main.o sniffer.o parse_packet.o arp.o routingTable.o writePacket.o icmp.o
	g++ -o local_router localhost_main.o sniffer.o parse_packet.o arp.o routingTable.o writePacket.o icmp.o -D_REETRANT -lpthread -lpcap

main.o: main.cc
	g++ -c -g main.cc  -D_REETRANT -lpthread -lpcap

localhost_main.o: localhost_main.cc
	g++ -c -g localhost_main.cc  -D_REETRANT -lpthread -lpcap

sniffer.o: sniffer.cc
	g++ -c -g sniffer.cc  -D_REETRANT -lpthread -lpcap

parse_packet.o: parse_packet.cc
	g++ -c -g parse_packet.cc  -D_REETRANT -lpthread -lpcap

arp.o: arp.cc
	g++ -c -g arp.cc  -D_REETRANT -lpthread -lpcap

routingTable.o: routingTable.cc
	g++ -c -g routingTable.cc  -D_REETRANT -lpthread -lpcap

writePacket.o:  writePacket.cc
	g++ -c -g writePacket.cc  -D_REETRANT -lpthread -lpcap

icmp.o: icmp.cc
	g++ -c -g icmp.cc  -D_REETRANT -lpthread -lpcap

clean:
	rm -rf *.o router local_router
