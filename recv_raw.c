#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include "raw.h"

#define PROTO_UDP	17
#define DST_PORT	8000

char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22};
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33};

int main(int argc, char *argv[])			//COMEÇA NA 123
{
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;
	
	/* Get interface name */
	if (argc > 1)										//mudou aqui de 1 para 2
		strcpy(ifName, argv[1]);						//aqui tbm
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
		perror("socket");
	
	/* Set interface to promiscuous mode */
	strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
	ifopts.ifr_flags |= IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

	/* End of configuration. Now we can receive data using raw sockets. */

	while (1){
		numbytes = recvfrom(sockfd, raw_buffer, ETH_LEN, 0, NULL, NULL);
		if (raw->ethernet.eth_type == ntohs(ETH_P_IP)){														//mudou parâmetros e conteúdo do if
			printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
				numbytes,
				raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3],
				raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3],
				raw->ip.proto
			);
			if (raw->ip.proto == PROTO_UDP && raw->udp.dst_port == ntohs(DST_PORT)){
				p = (char *)&raw->udp + ntohs(raw->udp.udp_len);
				*p = '\0';
				printf("src port: %d dst port: %d size: %d msg: %s", 
				ntohs(raw->udp.src_port), ntohs(raw->udp.dst_port),
				ntohs(raw->udp.udp_len), (char *)&raw->udp + sizeof(struct udp_hdr_s)
				); 
			}
			continue;
		}
				
		printf("got a packet, %d bytes\n", numbytes);
	}

	return 0;
}
