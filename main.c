/* main.c */
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ether.h>		/* for ether_aton() */
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>			/* for inet_addr() */
#include "net_header.h"			/* Net Header Structure */
#include <dumpcode.h>

/*
 *  send_arp
 *  return : true(0), false(-1)
 *  make a arp packet & send a arp packet
 */
#define ETHER_SIZE  sizeof(struct libnet_ethernet_hdr)
#define ARP_SIZE    sizeof(struct libnet_arp_hdr)
#define ARP_DATA    sizeof(struct _arp_data)
#define PACKET_SIZE 256

int send_arp(pcap_t *handle, pether_hdr peh, parp_hdr pah, parp_data pad) {
    u_char packet[PACKET_SIZE] = {0, };

    memcpy(packet, peh, ETHER_SIZE);
    memcpy(packet+ETHER_SIZE, pah, ARP_SIZE);
    memcpy(packet+ETHER_SIZE+ARP_SIZE, pad, ARP_DATA);
    dumpcode(packet, PACKET_SIZE);
    if(pcap_sendpacket(handle, packet, ETHER_SIZE+ARP_SIZE+ARP_DATA) != 0)
	return -1;

    return 0;
}


/*
 *  recv_arp
 *  return : true(0), false(-1)
 *  receive a arp reply packet
 */

void recv_arp(pcap_t *handle) {
    struct pcap_pkthdr header;        /* The header that pcap gives us */
    const u_char *packet;                   /* The actual packet */
    //DWORD offset = 0;

    while(1) {
	if(pcap_next_ex(handle, (struct pcap_pkthdr **)&header, &packet) == 1) {
	    if(((pether_hdr)packet)->ether_type == htons(ETHERTYPE_ARP)) {
		packet += ETHER_SIZE;

		if(((parp_hdr)packet)->ar_op == htons(ARPOP_REPLY)) {
		    packet += ARP_SIZE;

		    printf("Target MAC Address : %s\n", ether_ntoa(((parp_data)packet)->sender_ha));
		} else continue;
	    }
	}
    }

    //return 0;
}


/*
 *  normal_arp
 *  return : X
 *  normal arp request & reply
 */
void normal_arp(pcap_t *handle, const char* smac, const char* sip, const char* tip) {
    ether_hdr eh;			/* Ethernet Header */
    arp_hdr ah;				/* ARP Header */
    arp_data ad;			/* ARP Data */

    /* Setting Ethernet_Header */
    memset(&eh.ether_dhost, -1, ETHER_ADDR_LEN);
    memcpy(&eh.ether_shost, ether_aton(smac), ETHER_ADDR_LEN);
    eh.ether_type = ntohs(ETHERTYPE_ARP);

    /* Setting ARP_Header */
    ah.ar_hrd = ntohs(ARPHRD_ETHER);
    ah.ar_pro = ntohs(ETHERTYPE_IP);
    ah.ar_hln = ETHER_ADDR_LEN;
    ah.ar_pln = IP_ADDR_LEN;
    ah.ar_op = ntohs(ARPOP_REQUEST);

    /* Setting ARP_Data */
    memcpy(&ad.sender_ha, ether_aton(smac), ETHER_ADDR_LEN);
    ad.sender_ip = inet_addr(sip);
    memset(&ad.target_ha, 0, ETHER_ADDR_LEN);
    ad.target_ip = inet_addr(tip);

    if(send_arp(handle, &eh, &ah, &ad))
	printf("Error!");		// will modify

    recv_arp(handle);
}


/*
 *  convrt_mac
 *  return : X
 *  Convert 6 bytes address to MAC Address string
 */
void convrt_mac( const char *data, char *cvrt_str, int sz )
{
    char buf[64] = {0, };
    char t_buf[8];
    char *stp = strtok( (char *)data , ":" );
    int temp=0;
    do
    {
        memset( t_buf, 0x0, sizeof(t_buf) );
        sscanf( stp, "%x", &temp );
        snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
        strncat( buf, t_buf, sizeof(buf)-1 );
        strncat( buf, ":", sizeof(buf)-1 );
    } while( (stp = strtok( NULL , ":" )) != NULL );
    buf[strlen(buf) -1] = '\0';
    strncpy( cvrt_str, buf, sz );
}


/*
 *  get_sender_MAC
 *  return : true(0), false(-1)
 *  Get sender's MAC Address
 */
#define REQ_CNT 20

int get_sender_mac(char* mac_adr)
{
    int sockfd, cnt, req_cnt = REQ_CNT;
    struct ifconf ifcnf_s;
    struct ifreq *ifr_s;
    sockfd = socket( PF_INET , SOCK_DGRAM , 0 );
    if( sockfd < 0 ) {
	perror( "socket()" );
	return -1;
    }
    memset( (void *)&ifcnf_s , 0x0 , sizeof(ifcnf_s) );
    ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
    ifcnf_s.ifc_buf = malloc(ifcnf_s.ifc_len);
    if( ioctl( sockfd, SIOCGIFCONF, (char *)&ifcnf_s ) < 0 ) {
        perror( "ioctl() - SIOCGIFCONF" );
        return -1;
    }
    
    if( ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt) ) {
        req_cnt = ifcnf_s.ifc_len;
        ifcnf_s.ifc_buf = realloc( ifcnf_s.ifc_buf, req_cnt );
    }
    ifr_s = ifcnf_s.ifc_req;
    for( cnt = 0 ; cnt < ifcnf_s.ifc_len ; cnt += sizeof(struct ifreq), ifr_s++ )
    {
        if( ioctl( sockfd, SIOCGIFFLAGS, ifr_s ) < 0 ) {
            perror( "ioctl() - SIOCGIFFLAGS" );
            return -1;
        }
        
	if( ifr_s->ifr_flags & IFF_LOOPBACK )
            continue;
        if( ioctl( sockfd, SIOCGIFHWADDR, ifr_s ) < 0 ) {
            perror( "ioctl() - SIOCGIFHWADDR" );
            return -1;
        }
        convrt_mac(ether_ntoa((struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), mac_adr, 63);
	printf("Sender MAC Address : %s\n", mac_adr);
    }

    free(ifcnf_s.ifc_buf);
    return 0;
}


/*
 *  main
 *  return : true(0), false
 *  Main Function
 */
#define PROMISC	    1
#define NONPROMISC  0
#define TIME_OUT    1000

int main(int argc, char *argv[]) {
    pcap_t *handle;			/* Session Handle */
    char *dev;				/* Interface */
    char *sip;				/* Sender IP */
    char *tip;				/* Target IP */
    char smac[64] = {0, };		/* Sender MAC */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error String */

    if(argc!=4) {
        fprintf(stderr, "Usage : %s <interface> <sender ip> <target ip>\n", argv[0]);
        return(2);
    }
    dev = argv[1];
    sip = argv[2];
    tip = argv[3];

    get_sender_mac(smac);

    /* Nonpromiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, PROMISC, TIME_OUT, errbuf);
    if (handle == NULL) {
    	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    	return(2);
    }

    // Get MAC Address
    normal_arp(handle, smac, sip, tip);

    /* And close the session */
    pcap_close(handle);
	    
    return(0);
}
