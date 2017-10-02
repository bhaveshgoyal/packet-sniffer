#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
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

	pcap_close(handle);
	return 0;
}
