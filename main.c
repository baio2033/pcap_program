#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

	struct ether_header{
		u_char dst[6];
		u_char src[6];
		u_char type[2];
	};

	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};

	struct tcp_header{
		u_short tcp_src;
		u_short tcp_dst;
		u_char tcp_seq[4];
		u_char tcp_acknum[4];
		u_char tcp_offetc[4];
		u_char chksum[2];
		u_char ptr[2];
		u_char option[4];
	};


int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr header;
	int idx = 0;
	char filter_exp[] = "port 80";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	struct ether_header ether;
	struct sniff_ip *ip;
	struct tcp_header *tcp;

	u_char *data;
	int opt = 1;
	
	dev = pcap_lookupdev(errbuf);

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
	packet = pcap_next(handle,&header);
	printf("=====================================================\n");
	printf("[+] Jacked packet length : %d\n\n", header.len);
	for(int i=0;i<header.len;i++){
		if(i<6){
			if(idx == 0)
				printf("[+] DST MAC : ");
			printf("%02x",*packet);
			ether.dst[idx++] = *packet++;	
			if(idx != 6) printf(":");
			if(idx == 6) {
				idx = 0;
				printf("\n");
			}
		}
		else if(i<12){
			if(idx == 0)
				printf("[+] SRC MAC : ");
			printf("%02x",*packet);	
			ether.src[idx++] = *packet++;
			if(idx != 6) printf(":");
			if(idx == 6){
			 	idx = 0;
				printf("\n");
			}
		}
		else if(i<14){
			ether.type[idx++] = *packet++;
			if(idx == 2){
				idx = 0;
				printf("\n");
			}
		}
		else if(i<34){
			ip = (struct sniff_ip*)(packet);
			printf("[+] SRC IP : %s\n",inet_ntoa(ip->ip_src));
			printf("[+] DST IP : %s\n",inet_ntoa(ip->ip_dst));
			i = 34;
			packet += 20;
			printf("\n");
		}
		else if(i<54){
			tcp = (struct tcp_header*)(packet);
			printf("[+] SRC TCP : %d\n",ntohs(tcp->tcp_src));
			printf("[+] DST TCP : %d\n",ntohs(tcp->tcp_dst));
			i = 54;
		}
		else if(i >= 54){
			data = (u_char *)(packet+20);
			printf("\n[+]Data section\n");
			printf("%s\n",data);
			printf("\n[+] Press 1 and Enter to continue or Press 2 and Enter to exit\n");
			scanf("%d",&opt);
			if(opt == 2){
				printf("\n");
				pcap_close(handle);
				return 0;
			}
			break;
		}
	}
	}


	return 0;
}
