#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "lib/defs.h"
#include "lib/format.c"
#define EXP_LEN 100
#define SIZE_ETHERNET 14
#define MAX_PLOAD_SIZE 70000
int sflag = 0;
char *sload = NULL;
u_char pload_buff[MAX_PLOAD_SIZE] = {0};
long long idx = 0;
void
store_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	const u_char *ch;
	
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			pload_buff[idx++] = *ch;
		ch++;
	}
return;
}

void
store_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		store_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		store_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			store_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
return;
}

void print_ether_type(u_short ether_type, u_char *ether_dhost, u_char *ether_shost){

		for(int i = 0; i < 6; i++){
				printf("%02x", ether_shost[i]);
				if (i <= 4)
						printf(":");
				else
						printf(" > ");
		}
		for(int i = 0; i < 6; i++){
				printf("%02x", ether_dhost[i]);
				if (i <= 4)
						printf(":");
				else{
						printf(" type 0x%03hx", ntohs(ether_type));
				}
		}

		return;
}
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

		const struct sniff_ethernet *ethernet;  
		const struct sniff_ip *ip;                 
		const struct sniff_tcp *tcp;             
		const struct sniff_udp *udp;
		const struct icmp *icmphd;
		u_char *payload;                     
		char *type;
		int ip_size, tcp_size, udp_size, pload_size;
		int src_port, dst_port;
		bpf_int32 *packet_size;
		char src_ip[16], dst_ip[16];


		ethernet = (struct sniff_ethernet*)(packet);



		time_t timer;
		char buffer[26];

		// Print time of capture
		const time_t *pkt_time	 = (time_t *)(&header->ts.tv_sec);
		bpf_int32 *micro = (bpf_int32 *)&header->ts.tv_usec;
		strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", localtime(pkt_time));

		packet_size = (bpf_int32*)&header->len;


		uint16_t p_type = ntohs(ethernet->ether_type);
		if (p_type == ETHERTYPE_ARP){
				const struct sniff_arp *arp;           
				arp = (struct sniff_arp*)(packet + ETHER_SIZE);
				snprintf (dst_ip, 16, "%d.%d.%d.%d",
								arp->arp_dip[0], arp->arp_dip[1], arp->arp_dip[2], arp->arp_dip[3]);
				snprintf (src_ip, 16, "%d.%d.%d.%d",
								arp->arp_sip[0], arp->arp_sip[1], arp->arp_sip[2], arp->arp_sip[3]);

				printf("%s.%06d ", buffer, *micro);
				printf (" len %d ARP, Request who-has %s tell %s\n", *packet_size - ETHER_SIZE, dst_ip, src_ip);
		}
		else if (p_type == ETHERTYPE_IP){
				ip = (struct sniff_ip*)(packet+ETHER_SIZE);
				ip_size = IP_HL(ip)*4;
				if (ip_size < 20)
						return;
				
				strcpy(src_ip, inet_ntoa(ip->ip_src));
				strcpy(dst_ip, inet_ntoa(ip->ip_dst));

				switch(ip->ip_p){
						case IPPROTO_TCP:
								type = "TCP";
								tcp = (struct sniff_tcp*)(packet + ETHER_SIZE + ip_size);
								tcp_size = TH_OFF(tcp)*4;
								if (tcp_size < 20){
										return;
								}
								src_port = ntohs(tcp->th_sport);
								dst_port = ntohs(tcp->th_dport);
								payload = (u_char *)(packet + ETHER_SIZE + ip_size + tcp_size);
								pload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);
								if (sflag == 1 && sload){
										if (pload_size == 0)
												break;
										else{
												store_payload(payload, pload_size);
												if (strstr((const char *)pload_buff, sload) == NULL){
														idx = 0;
														memset(&pload_buff, 0, sizeof(pload_buff));
														return;
												}
										}
								}
								printf("%s.%06d ", buffer, *micro);
								print_ether_type(ethernet->ether_type, (u_char *)ethernet->ether_dhost, (u_char *)ethernet->ether_shost);
								printf(" len %d %s:%d > %s:%d %s\n", *packet_size - ETHER_SIZE, src_ip, src_port, dst_ip, dst_port, type);
								print_payload(payload, pload_size);
								printf("\n");
								break;
						case IPPROTO_UDP:
								udp = (struct sniff_udp*)(packet + ETHER_SIZE + ip_size);
								udp_size = (ntohs(udp->len));
								if (udp_size < 8)
										return;
								type = "UDP";
								src_port = ntohs(udp->udp_sport);
								dst_port = ntohs(udp->udp_dport);
								payload = (u_char *)(packet + ETHER_SIZE + ip_size + 8);
								pload_size = ntohs(ip->ip_len) - (ip_size + 8);
								if (sflag == 1 && sload){
										if (pload_size == 0)
												return;
										else{
												store_payload(payload, pload_size);
												if (strstr((const char *)pload_buff, sload) == NULL){
														idx = 0;
														memset(&pload_buff, 0, sizeof(pload_buff));
														return;
												}
										}
								}
								printf("%s.%06d ", buffer, *micro);
								print_ether_type(ethernet->ether_type, (u_char *)ethernet->ether_dhost, (u_char *)ethernet->ether_shost);
								printf(" len %d %s:%d > %s:%d %s\n", udp_size, src_ip, src_port, dst_ip, dst_port, type);
								print_payload(payload, pload_size);
								printf("\n");
								break;
						case IPPROTO_ICMP:
								type = "ICMP";
								printf("%s.%06d ", buffer, *micro);
								icmphd = (struct icmp*)(packet + ETHER_SIZE + ip_size);
								unsigned short id, seq;
								memcpy(&id, (u_char*)icmphd+4, 2);
								memcpy(&seq, (u_char*)icmphd+6, 2);
								char *type;
								payload = (u_char *)(packet + ETHER_SIZE + ip_size + 8);
								pload_size = ntohs(ip->ip_len) - (ip_size + 8);
								if (sflag == 1 && sload){
										if (pload_size == 0)
												return;
										else{
												store_payload(payload, pload_size);
												if (strstr((const char *)pload_buff, sload) == NULL){
														idx = 0;
														memset(&pload_buff, 0, sizeof(pload_buff));
														return;
												}
										}
								}
								if (icmphd->icmp_type == 8)
										type = "request";
								else if (icmphd->icmp_type == 0)
										type = "reply";
								if (icmphd->icmp_type == 3)
										type = "unreachable";
								printf("IP %s > %s: ICMP echo %s ,id %d, seq %d\n", src_ip, dst_ip, type, ntohs(id), ntohs(seq));
								print_payload(payload, pload_size);
								printf("\n");
								break;
						case IPPROTO_IGMP:
								type = "IGMP";
								printf("%s.%06d ", buffer, *micro);
								print_ether_type(ethernet->ether_type, (u_char *)ethernet->ether_dhost, (u_char *)ethernet->ether_shost);
								printf(" IP %s > %s: IGMP\n", src_ip, dst_ip);
								break;
						default:
								type = "Unknown Protocol";
								printf("%s.%06d ", buffer, *micro);
								print_ether_type(ethernet->ether_type, (u_char *)ethernet->ether_dhost, (u_char *)ethernet->ether_shost);
								printf(" IP %s > %s type %s\n", src_ip, dst_ip, type);
								break;
				}

//				printf("\n");
		}
		idx = 0;
		memset(&pload_buff, 0, sizeof(pload_buff));
		return;
}
int main(int argc, char **argv){

		int iflag = 0, rflag = 0;
		char *iface = NULL, *rfile = NULL;
		char exp[EXP_LEN] = {0}, errbuf[PCAP_ERRBUF_SIZE];
		int opt;
		pcap_t *handle;
		struct pcap_pkthdr header;
		const u_char *packet;		
		struct bpf_program filter;
		bpf_u_int32 mask, net;


		while((opt = getopt(argc, argv, "i:r:s:")) != -1){
				switch(opt)
				{
						case 'i':
								iflag = 1;
								iface = optarg;
								break;
						case 'r':
								rflag = 1;
								rfile = optarg;
								break;
						case 's':
								sflag = 1;
								sload = optarg;
								break;
						case ':':
								fprintf(stderr, "requires an argument");
								break;
						case '?':
								if (optopt == 'i' || optopt == 'r' || optopt == 's')
										fprintf(stderr, "Option %c requires an argument\n", optopt);
								else{
										fprintf(stderr, "Invalid option %c to program\n", optopt);
								}
								return 1;
						default:
								exit(0);
				}
		}
//		printf("%s %s %s %s", iface, rfile, sload, exp);
//		printf("%d %d %d", iflag, rflag, sflag);

		for(int i = optind; i < argc; i++){
			strcat(exp, argv[i]);
			printf("Expression: %s ", argv[i]);
		}
		if (strlen(exp) > 0){	
				if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1){
						fprintf(stderr, "Could not fetch net mask for device %s", iface);
						net = 0;
						mask = 0;
				}
		}
		if (!iface && iflag == 0){
				iface = pcap_lookupdev(errbuf);
				if (iface == NULL) {
						fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
						exit(0);
				}
		}
		if (rflag == 1 && rfile){
				printf("Reading dump from file: %s\n", rfile);
				handle = pcap_open_offline(rfile, errbuf);
				if (!handle){
						fprintf(stderr, "Error reading dump: %s\n", errbuf);
						exit(0);
				}
				else if (pcap_datalink(handle) != DLT_EN10MB) {
						fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", iface);
						exit(0);
				}

		}
		else{
				printf("Sniffing on device: %s\n", iface);
				handle = pcap_open_live(iface, 1518, 1, 1000, errbuf);
				if (handle == NULL) {
						fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
						exit(0);
				}
				else if (pcap_datalink(handle) != DLT_EN10MB) {
						fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", iface);
						exit(0);
				}
		}
		if (pcap_compile(handle, &filter, exp, 0, net) == -1){
			fprintf(stderr, "Could not parse filter %s: %s\n", exp, pcap_geterr(handle));
			exit(0);
		}
		if (pcap_setfilter(handle, &filter) == -1){
			fprintf(stderr, "Could not install filter %s: %s\n", exp, pcap_geterr(handle));
			exit(0);
		}

		pcap_loop(handle, -1, packet_handler, NULL);
		pcap_freecode(&filter);
		pcap_close(handle);

		return 0;
}
