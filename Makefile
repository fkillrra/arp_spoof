all : arp_spoof

arp_spoof : main.o
	g++ -g -o arp_spoof main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f arp_spoof
	rm -f *.o

