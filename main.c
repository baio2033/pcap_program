#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>

#define ETHER_SIZE 14
#define ETHER_ADDR_LEN 6

u_int16_t total_len = 0;
u_int16_t cur_len = 0;
u_int16_t ip_size = 0;
u_int16_t tcp_size = 0;

void func_ether(u_char* packet);
void func_ip(u_char* packet);
void func_tcp(u_char* packet);

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


void func_ether(u_char* packet){
	struct ether_header *ether = (struct ether_header*)(packet);

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

	if(ntohs(ether->ether_type) == 0x0800){
		cur_len = ETHER_SIZE;
		func_ip(packet);
	}
	else{
		return;
	}
}


void func_ip(u_char* packet){
	char buf[INET_ADDRSTRLEN];
	

	struct ip_header *ip = (struct ip_header*)(packet+ETHER_SIZE);
	printf("\n[+] IP header information...\n");
	printf("source IP : %s\n",inet_ntop(AF_INET,&(ip->ip_src.s_addr),buf,INET_ADDRSTRLEN));
	printf("destination IP : %s\n",inet_ntop(AF_INET,&(ip->ip_dst.s_addr),buf,INET_ADDRSTRLEN));
	ip_size = ip->ip_hl*4;
	printf("ip_size : %d\n",ip_size);
	printf("total length of packet : %d\n",ip->ip_len);
	total_len = ip->ip_len;	
	if(ip->ip_proto == 0x06){
		cur_len += ip_size;
		func_tcp(packet);
	}
	else
		return;
}

void func_tcp(u_char* packet){
	u_char *data;
	struct tcp_header *tcp = (struct tcp_header*)(packet+ETHER_SIZE+ip_size);
	tcp_size = tcp->tcp_off*4;
	printf("\n[+] TCP header information...\n");
	printf("TCP source port : %d\n",ntohs(tcp->tcp_src));
	printf("TCP destination port : %d\n",ntohs(tcp->tcp_dst));
	printf("TCP size : %d\n",tcp_size);
	
	cur_len += tcp_size;
	if(total_len > cur_len){
		printf("\n[+] Data Section (16 bytes hex values)\n");
		data = packet+ETHER_SIZE+ip_size+tcp_size;
		for(int i=0;i<16;i++)
			printf("%02x ",data[i]);
	}
	printf("\n");
	return;
}

int main(int argc, char* argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet,*pk_data;
	struct pcap_pkthdr header;
	int idx = 0;
	u_char *packet_ptr;
	int ret;
	int cnt = 0;
	struct ether_header *ether;
	struct ip_header *ip;
	struct tcp_header *tcp;

	u_char *data;

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
	
	while(1){
		ret = pcap_next_ex(handle,&header,&pk_data);	
		if(ret == 0){
			printf("[+] time out...\n");
			continue;
		}
		else if(ret < 0){
			printf("[+] fail to receive packet!\n");
			break;
		}
		else{
			for(int i=0;i<header.len;i++){
				printf("%02x ",*(packet_ptr++));
				if(i%16==0 && i!=0) printf("\n");
			}

			printf("\n");
			printf("###################### frame [%d] #############################\n",cnt++);
			func_ether(pk_data);
			printf("###############################################################\n\n");
		}
	}
	return 0;
}

	 
