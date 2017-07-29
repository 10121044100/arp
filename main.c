/* main.c */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "net_header.h"		/* Net Header Structure */

#define ETHER_SIZE  sizeof(struct libnet_ethernet_hdr)
#define ARP_SIZE    sizeof(struct libnet_arp_hdr)
#define PACKET_SIZE 256

int send_arp(pcap_t *handle) {
    struct libnet_ethernet_hdr leh;		/* Ethernet Header */
    struct libnet_arp_hdr lah;			/* ARP Header */
    u_char packet[PACKET_SIZE] = {0, };

    memcpy(packet, &leh, ETHER_SIZE);
    memcpy(packet+ETHER_SIZE, &lah, ARP_SIZE);
    if(pcap_sendpacket(handle, packet, PACKET_SIZE))
	return -1;

    return 0;
}

#define NONPROMISC  0
#define TIME_OUT    1000

int main(int argc, char *argv[]) {
    pcap_t *handle;			/* Session Handle */
    char *dev;				/* Interface */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error String */
    struct pcap_pkthdr header;		/* The header that pcap gives us */
    u_char *packet;			/* The actual packet */

    if(argc!=4) {
        fprintf(stderr, "Usage : %s <interface> <sender ip> <target ip>\n", argv[0]);
        return(2);
    }
    dev = argv[1];

    /* Nonpromiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, NONPROMISC, TIME_OUT, errbuf);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    	return(2);
    }

    // Get MAC Address
    //send_arp(handle);

    /* And close the session */
    pcap_close(handle);
	    
    return(0);
}
