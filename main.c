/* main.c */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ether.h>		/* for ether_aton() */
#include <arpa/inet.h>			/* for inet_addr() */
#include "net_header.h"			/* Net Header Structure */

#define MY_MAC "e4:42:a6:a1:a7:b6"

#define ETHER_SIZE  sizeof(struct libnet_ethernet_hdr)
#define ARP_SIZE    sizeof(struct libnet_arp_hdr)
#define ARP_DATA    sizeof(struct arp_data)
#define PACKET_SIZE 256

int send_arp(pcap_t *handle, pether_hdr peh, parp_hdr pah, parp_data pad) {
    u_char packet[PACKET_SIZE] = {0, };

    memcpy(packet, peh, ETHER_SIZE);
    memcpy(packet+ETHER_SIZE, pah, ARP_SIZE);
    memcpy(packet+ETHER_SIZE+ARP_SIZE, pad, ARP_DATA);
    if(pcap_sendpacket(handle, packet, ETHER_SIZE+ARP_SIZE+ARP_DATA))
	return -1;

    return 0;
}

void normal_arp(pcap_t *handle, const char* sip, const char* tip) {
    ether_hdr eh;			/* Ethernet Header */
    arp_hdr ah;				/* ARP Header */
    arp_data ad;			/* ARP Data */

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

    /* Setting ARP_Data */
    memcpy(&ad.sender_ha, ether_aton(MY_MAC), ETHER_ADDR_LEN);
    ad.sender_ip = inet_addr(sip);
    memset(&ad.target_ha, 0, ETHER_ADDR_LEN);
    ad.target_ip = inet_addr(tip);

    if(send_arp(handle, &eh, &ah, &ad))
	printf("Error!");		// will modify

}

#define PROMISC	    1
#define NONPROMISC  0
#define TIME_OUT    1000

int main(int argc, char *argv[]) {
    pcap_t *handle;			/* Session Handle */
    char *dev;				/* Interface */
    char *sip;				/* Sender IP */
    char *tip;				/* Target IP */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error String */
    //struct pcap_pkthdr header;		/* The header that pcap gives us */
    //u_char *packet;			/* The actual packet */

    if(argc!=4) {
        fprintf(stderr, "Usage : %s <interface> <sender ip> <target ip>\n", argv[0]);
        return(2);
    }
    dev = argv[1];
    sip = argv[2];
    tip = argv[3];

    /* Nonpromiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, NONPROMISC, TIME_OUT, errbuf);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    	return(2);
    }

    // Get MAC Address
    normal_arp(handle, sip, tip);

    /* And close the session */
    pcap_close(handle);
	    
    return(0);
}
