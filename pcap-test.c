#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}
\

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        printf("=====packet capture=====\n");

        // ethernet header
        struct libnet_ethernet_hdr* ethHdr;
        ethHdr = (struct libnet_ethernet_hdr*)(packet);

        printf("src mac: ");
        for (int i=0; i<6; i++){
            printf("%x ", ethHdr->ether_shost[i]);
        }
        printf("\n");

        printf("dst mac: ");
        for (int i=0; i<6; i++){
            printf("%x ", ethHdr->ether_dhost[i]);
        }
        printf("\n");

        // ipv4 header
        struct libnet_ipv4_hdr* ipv4Hdr;
        ipv4Hdr = (struct libnet_ipv4_hdr*)(packet+14);

        printf("src ip: ");
        char* srcIp = inet_ntoa((ipv4Hdr->ip_src));
        printf("%s", srcIp);
        printf("\n");

        printf("dst ip: ");
        char* dstIp = inet_ntoa((ipv4Hdr->ip_dst));
        printf("%s", dstIp);
        printf("\n");

        // tcp header
        struct libnet_tcp_hdr* tcpHdr;
        tcpHdr = (struct libnet_tcp_hdr*)(packet+34);
        printf("src port: ");
        printf("%d", ntohs(tcpHdr->th_sport));
        printf("\n");
        printf("dst port: ");
        printf("%d", ntohs(tcpHdr->th_dport));
        printf("\n");

        // payload(data)
        unsigned char *payload;
        payload = (unsigned char *)(packet + 54);
        printf("payload: ");
        
        for(int i=0;i<8;i++){
            printf("%x ", payload[i]);
        }
        printf("\n\n");

        // printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}
