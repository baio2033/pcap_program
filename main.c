#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define ETHER_SIZE 14
#define ETHER_ADDR_LEN 6

u_int16_t ip_size = 0;
u_int16_t tcp_size = 0;

struct ether_header{
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;
};

struct ip_header{
	u_int8_t ip_hl:4,ip_v:4;
	u_int8_t ip_tos;
	u_int16_t ip_len;	// ip total length
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_proto;
	u_int16_t ip_sum;
	struct in_addr ip_src,ip_dst;
};

struct tcp_header{
	u_int16_t tcp_src;
	u_int16_t tcp_dst;
	u_int32_t tcp_seq;
	u_int32_t tcp_ack;
	u_int8_t tcp_rev:4,tcp_off:4;
	u_int8_t tcp_flag;
	u_int16_t tcp_win;
	u_int16_t tcp_sum;
	u_int16_t tcp_ptr;
};


int func_ether(u_char* packet, struct ether_header *ether){
	ether = (struct ether_header*)(packet);
	if(ntohs(ether->ether_type) == 0x0800){
	
	printf("[+] Ethernet header information...\n");
	printf("Destination MAC : ");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ether->ether_dhost[i]);
		if(i<ETHER_ADDR_LEN-1) printf(":");
		else printf("\n");
	}
	printf("Source MAC : ");
	for(int i=0;i<ETHER_ADDR_LEN;i++){
		printf("%02x",ether->ether_shost[i]);
		if(i<ETHER_ADDR_LEN-1) printf(":");
		else printf("\n");
	}
		return 1;
	}
	else{
		return -1;
	}
}


int func_ip(u_char* packet, struct ip_header *ip){
	char buf[INET_ADDRSTRLEN];
	ip = (struct ip_header*)(packet+ETHER_SIZE);
	if(ip->ip_proto == 0x06){
	printf("\n\n[+] IP header information...\n");
	printf("source IP : %s\n",inet_ntop(AF_INET,&(ip->ip_src.s_addr),buf,INET_ADDRSTRLEN));
	printf("destination IP : %s\n",inet_ntop(AF_INET,&(ip->ip_dst.s_addr),buf,INET_ADDRSTRLEN));
	ip_size = ip->ip_hl*4;
	printf("ip_size : %d\n",ip_size);
	}
	else{
		return -1;
	}
}

void func_tcp(u_char* packet, struct tcp_header *tcp){
	tcp = (struct tcp_header*)(packet+ETHER_SIZE+ip_size);
	tcp_size = tcp->tcp_off*4;
	printf("\n\n[+] TCP header information...\n");
	printf("TCP source port : %d\n",ntohs(tcp->tcp_src));
	printf("TCP destination port : %d\n",ntohs(tcp->tcp_dst));
	printf("TCP size : %d\n",tcp_size);
}

void func_data(u_char* packet){
	u_char *data = packet+ETHER_SIZE+ip_size+tcp_size;
	printf("\n\n[+] data section...\n");
	printf("%s",data);
}

int main(int argc, char* argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet,*pk_data;
	struct pcap_pkthdr header;
	int idx = 0;
	char filter_exp[] = "port 80";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	u_char *packet_ptr;

	struct ether_header *ether;
	struct ip_header *ip;
	struct tcp_header *tcp;

	u_char *data;
	int opt = 1;

	//dev = pcap_lookupdev(errbuf);
	//dev = "dum0";
	dev = argv[1];

	if(dev == NULL){
		printf("[+] Cannot find default device!\n");
		return 0;
	}
	printf("device : %s\n",dev);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		printf("[+] Cannot open the device!\n");
		return 0;
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	while(1){
		printf("\n\n[+] capture the packet\n\n");
		packet = pcap_next_ex(handle,&header,&pk_data);	
		packet_ptr = packet;
		for(int i=0;i<header.len;i++){
			printf("%02x ",*(packet_ptr++));
			if(i%16==0 && i!=0) printf("\n");
		}

		printf("\n");

		func_ether(pk_data,ether);
		func_ip(pk_data,ip);
		
		func_tcp(pk_data,tcp);
		func_data(pk_data);

		if(packet < 0) break;
		else continue;
		//printf(">>>>> ");
		//scanf("%d",&opt);
		//if(opt == 1) break;
		//else continue;
	}
	return 0;
}

	 
