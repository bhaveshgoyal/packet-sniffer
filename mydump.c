#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <time.h>
#include <math.h>
#include "lib/defs.h"
#include "lib/format.c"

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
//	static int packet_count = 1;

	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const u_char *payload;                    /* Packet payload */
	char * src_ip, *dst_ip, *type;
	int ip_size, tcp_size, pload_size, packet_size;
	int src_port, dst_port;
	
	time_t timer;
    char buffer[26];
    struct tm* tm_info;
	struct timeval tv;
	int millisec;
	
	gettimeofday(&tv, NULL);

    tm_info = localtime(&tv.tv_sec);
	millisec = lrint(tv.tv_usec); // Round to nearest millisec
  	if (millisec>=1000000) { // Allow for rounding up to nearest second
    	millisec -=1000000;
    	tv.tv_sec++;
  	}    

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	printf("%s.%06d ", buffer, millisec);
    
	ethernet = (struct sniff_ethernet*)packet;
	
	ip = (struct sniff_ip*)(packet+ETHER_SIZE);
	ip_size = IP_HL(ip)*4;
	if (ip_size < 20){
		printf("Invalid IP header length %u\n", ip_size);
		return;
	}

	tcp = (struct sniff_tcp*)(packet + ETHER_SIZE + ip_size);
	tcp_size = TH_OFF(tcp)*4;
	if (tcp_size < 20){
		printf("Invalid TCP header length: %u bytes\n", tcp_size);
		return;
	}
	payload = (u_char *)(packet + ETHER_SIZE + ip_size + tcp_size);

	src_ip = inet_ntoa(ip->ip_src);
	dst_ip = inet_ntoa(ip->ip_dst);
	src_port = ntohs(tcp->th_sport);
	dst_port = ntohs(tcp->th_dport);
	packet_size = ntohs(ip->ip_len);

	switch(ip->ip_p){
		case IPPROTO_TCP:
			type = "TCP";
			break;
		case IPPROTO_UDP:
			type = "UDP";
			return;
		case IPPROTO_ICMP:
			type = "ICMP";
			return;
		case IPPROTO_IP:
			type = "IP";
			return;
		default:
			type = "Unknown";
			return;
	}
 	
	for(int i = 0; i < 6; i++){
	    printf("%02x", ethernet->ether_shost[i]);
    	if (i <= 4)
			printf(":");
		else
			printf(" -> ");
	}
	for(int i = 0; i < 6; i++){
	    printf("%02x", ethernet->ether_dhost[i]);
    	if (i <= 4)
			printf(":");
		else{
			printf(" type 0x%03hx", ntohs(ethernet->ether_type));
		}
	}
	printf(" len %d %s:%d -> %s:%d %s\n", packet_size, src_ip, src_port, dst_ip, dst_port, type);
	
	pload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

	if (pload_size > 0) {
//		printf("   Payload (%d bytes):\n", pload_size);
		print_payload(payload, pload_size);
	}
	printf("\n");	
	return;
}
int main(int argc, char **argv){

	int iflag = 0, rflag = 0, sflag = 0;
	char *iface = NULL, *rfile = NULL, *sload = NULL;
	char *exp = NULL, errbuf[PCAP_ERRBUF_SIZE];
	int opt;
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;		

	while((opt = getopt(argc, argv, ":i:r:s:")) != -1){
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
	//		printf("%s %s %s", iface, rfile, sload);
	//		printf("%d %d %d", iflag, rflag, sflag);

	//	for(int i = optind; i < argc; i++){
	//		printf("Expression: %s ", argv[i]);
	//	}		
	if (!iface && iflag == 0){
			iface = pcap_lookupdev(errbuf);
			if (iface == NULL) {
					fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
					exit(0);
			}
	}
	printf("Sniffing on device: %s\n", iface);

	handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
		 exit(0);
	}
	else if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", iface);
		exit(0);
	}
	
	packet = pcap_next(handle, &header);
	printf("Jacked a packet with length of [%d]\n", header.len);

	pcap_loop(handle, -1, packet_handler, NULL);
	pcap_close(handle);
	return 0;
}
