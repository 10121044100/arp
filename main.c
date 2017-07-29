/* main.c */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>		/* for ether_aton() */
#include "net_header.h"			/* Net Header Structure */

#define MY_MAC "e4:42:a6:a1:a7:b6"

#define ETHER_SIZE  sizeof(struct libnet_ethernet_hdr)
#define ARP_SIZE    sizeof(struct libnet_arp_hdr)
#define PACKET_SIZE 256

int send_arp(pcap_t *handle, pether_hdr peh, parp_hdr pah) {
    u_char packet[PACKET_SIZE] = {0, };

    memcpy(packet, peh, ETHER_SIZE);
    memcpy(packet+ETHER_SIZE, pah, ARP_SIZE);
    if(pcap_sendpacket(handle, packet, ETHER_SIZE+ARP_SIZE))
	return -1;

    return 0;
}

void normal_arp(pcap_t *handle) {
    ether_hdr eh;			/* Ethernet Header */
    arp_hdr ah;				/* ARP Header */

    /* Setting Ethernet_Header */
    memset(&eh.ether_dhost, -1, ETHER_ADDR_LEN);
    memcpy(&eh.ether_shost, ether_aton(MY_MAC), ETHER_ADDR_LEN);
    eh.ether_type = ETHERTYPE_ARP;

    /* Setting ARP_Header */
    ah.ar_hrd = ARPHRD_ETHER;
    ah.ar_pro = ETHERTYPE_IP;
    ah.ar_hln = ETHER_ADDR_LEN;
    ah.ar_pln = IP_ADDR_LEN;
    ah.ar_op = ARPOP_REQUEST;

    if(send_arp(handle, &eh, &ah))
	printf("Error!");
}

#define PROMISC	    1
#define NONPROMISC  0
#define TIME_OUT    1000

int main(int argc, char *argv[]) {
    pcap_t *handle;			/* Session Handle */
    char *dev;				/* Interface */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error String */
    //struct pcap_pkthdr header;		/* The header that pcap gives us */
    //u_char *packet;			/* The actual packet */

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
    normal_arp(handle);

    /* And close the session */
    pcap_close(handle);
	    
    return(0);
}
