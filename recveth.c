/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#ifdef __linux__
#include <netinet/ether.h>
#endif
#define ETHER_TYPE	0x0800

#define DEFAULT_IF	"eth0"
#define BUF_SIZ		1024

int main(int argc, char *argv[])
{
	char sender[INET6_ADDRSTRLEN];
	int sockfd, ret, i;
	int sockopt;
	ssize_t numbytes;
	struct ifreq ifopts;	/* set promiscuous mode */
	struct ifreq if_ip;	/* get ip addr */
	struct sockaddr_storage their_addr;
	uint8_t buf[BUF_SIZ];
	char ifName[IFNAMSIZ];
	char talkative= 0;
	int c;
	char *macaddr= NULL;
	static unsigned char DEST_MAC[6];
	int dsttest= 1;
	int srctest= 0;
	
	opterr = 0;

	while ((c = getopt (argc, argv, "vsa:i:")) != -1) {
	  switch (c) {
	    case 's':
	      srctest= 1;
	      dsttest= 0;
	      break;
	    case 'v':
	      talkative= 1;
	      break;
	    case 'a':
	      macaddr= optarg;
	      if (macaddr) {
		int ndig= 0;
		char *sptr;
		char *dig = strtok_r(macaddr, ":", &sptr);
		do {
		  DEST_MAC[ndig++] = strtoul(dig, NULL, 16);
		  printf ("dig(%d)=0x%x\n", ndig-1, DEST_MAC[ndig-1]);
		} while ((dig= strtok_r(NULL, ":", &sptr)) && ndig < 6);
	      }
	      break;
	    case 'i':
	      strcpy(ifName, optarg);
	      break;
	    case '?':
	      if (optopt == 'a' || optopt == 'i')
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	      else if (isprint (optopt))
		fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	      else
		fprintf (stderr,
			 "Unknown option character `\\x%x'.\n",
			 optopt);
	      return 1;
	    default:
	      abort ();
	  }
	}

	/* Header structures */
	struct ether_header *eh = (struct ether_header *) buf;
	struct iphdr *iph = (struct iphdr *) (buf + sizeof(struct ether_header));
	struct udphdr *udph = (struct udphdr *) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

	memset(&if_ip, 0, sizeof(struct ifreq));

	/* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
	if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1) {
		perror("listener: socket");	
		return -1;
	}

	/* Set interface to promiscuous mode - do we need to do this every time? */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
	/* Allow the socket to be reused - incase connection is closed prematurely */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) == -1) {
		perror("setsockopt");
		close(sockfd);
		exit(EXIT_FAILURE);
	}
	/* Bind to device */
	if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)	{
		perror("SO_BINDTODEVICE");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

 repeat:	if (talkative) printf("listener: Waiting to recvfrom...\n");
	numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);
	if (talkative)
	  printf("listener: got packet %lu bytes\n", numbytes);

	/* Check the packet is for me */
	if (dsttest) {
		if (eh->ether_dhost[0] == DEST_MAC[0] &&
			eh->ether_dhost[1] == DEST_MAC[1] &&
			eh->ether_dhost[2] == DEST_MAC[2] &&
			eh->ether_dhost[3] == DEST_MAC[3] &&
			eh->ether_dhost[4] == DEST_MAC[4] &&
			eh->ether_dhost[5] == DEST_MAC[5]) {
		printf("Correct destination MAC address\n");
	} else {
	  if (talkative)
		printf("Wrong destination MAC: %x:%x:%x:%x:%x:%x\n",
						eh->ether_dhost[0],
						eh->ether_dhost[1],
						eh->ether_dhost[2],
						eh->ether_dhost[3],
						eh->ether_dhost[4],
						eh->ether_dhost[5]);
	  ret = -1;
	  goto done;
	}
	}

	if (srctest) {
		if (eh->ether_shost[0] == DEST_MAC[0] &&
			eh->ether_shost[1] == DEST_MAC[1] &&
			eh->ether_shost[2] == DEST_MAC[2] &&
			eh->ether_shost[3] == DEST_MAC[3] &&
			eh->ether_shost[4] == DEST_MAC[4] &&
			eh->ether_dhost[5] == DEST_MAC[5]) {
		printf("Correct source MAC address\n");
	} else {
	  if (talkative)
		printf("Wrong source MAC: %x:%x:%x:%x:%x:%x\n",
						eh->ether_shost[0],
						eh->ether_shost[1],
						eh->ether_shost[2],
						eh->ether_shost[3],
						eh->ether_shost[4],
						eh->ether_shost[5]);
	  ret = -1;
	  goto done;
	}
	}
	/* Get source IP */
	((struct sockaddr_in *)&their_addr)->sin_addr.s_addr = iph->saddr;
	inet_ntop(AF_INET, &((struct sockaddr_in*)&their_addr)->sin_addr, sender, sizeof sender);

	/* Look up my device IP addr if possible */
	strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFADDR, &if_ip) >= 0) { /* if we can't check then don't */
		printf("Source IP: %s\n My IP: %s\n", sender, 
				inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr));
		/* ignore if I sent it */
		if (strcmp(sender, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)	{
			printf("but I sent it :(\n");
			ret = -1;
			goto done;
		}
	}

	/* UDP payload length */
	ret = ntohs(udph->len) - sizeof(struct udphdr);

	/* Print packet */
	printf("\tData:");
	for (i=0; i<numbytes; i++) printf("%02x:", buf[i]);
	printf("\n");

done:	goto repeat;

	close(sockfd);
	return ret;
}
