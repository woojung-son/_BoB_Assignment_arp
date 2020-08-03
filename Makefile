LDLIBS=-lpcap

all: send-arp-test

send-arp-test: getmac.o getIpAddr.o main.o arphdr.o ethhdr.o ip.o mac.o
	#g++ -o send-arp-test arphdr.o ethhdr.o ip.o mac.o getmac.o -lpcap -std=gnu++11 -std=gnu++0x
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -std=c++11
	#arphdr.o ethhdr.o ip.o mac.o 	

arphdr.o: arphdr.h arphdr.cpp
	g++ -c -std=gnu++11 arphdr.cpp

ethhdr.o: ethhdr.h ethhdr.cpp
	g++ -c -std=gnu++11 ethhdr.cpp

ip.o: ip.h ip.cpp
	g++ -c -std=gnu++11 ip.cpp

mac.o: mac.h mac.cpp
	g++ -c -std=gnu++11 mac.cpp

getmac.o: getmac.h getmac.cpp
	g++ -c -std=gnu++0x -std=gnu++11 -lpcap getmac.cpp

getIpAddr.o: getIpAddr.h getIpAddr.cpp
	g++ -c -std=gnu++0x -std=gnu++11 -lpcap getIpAddr.cpp

main.o: main.cpp getmac.h ethhdr.h arphdr.h
	g++ -c -std=gnu++0x -std=gnu++11 -lpcap main.cpp

clean:
	rm -f send-arp-test *.o
