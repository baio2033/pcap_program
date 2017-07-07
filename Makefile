all: pcap.o pcap

pcap.o: main.c
		gcc -c main.c

pcap: main.o
		gcc -o pcap main.o -lpcap

clean:
		rm *.o
