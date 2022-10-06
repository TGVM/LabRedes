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

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22}; // trab não usa um valor definido de destino
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33}; //trab não usa src_mac

int main(int argc, char *argv[])					//começa na linha 252
{
	struct ifreq if_idx, if_mac, ifopts;
	char ifName[IFNAMSIZ];							//linha a + (a + pq já tem na parte do recvraw)
	struct sockaddr_ll socket_address;
	int sockfd, numbytes, size = 100;
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

	/* Get interface name */						//if a menos
	if (argc > 1)
		strcpy(ifName, argv[1]);
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

	/* Get the index of the interface */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;

	/* Get the MAC address of the interface */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		perror("SIOCGIFHWADDR");
	memcpy(this_mac, if_mac.ifr_hwaddr.sa_data, 6);

	/* End of configuration. Now we can send data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */

	/*
		2 SEÇÕES A + 

		L.290 pega target_mac [6] e faz cópia na memória(?)
		L.295 é um if pra ver se mensagem é tipo talk ou se é um heartbeat após ter 
		recebido o start, faz um memcpy e troca o valor de start_received (pq?)
	*/


	/* fill the Ethernet frame header */
	memcpy(raw->ethernet.dst_addr, bcast_mac, 6);
	memcpy(raw->ethernet.src_addr, src_mac, 6);
	raw->ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */

	// SEÇÃO ENTRE LINHAS 79 - 97 SUBSTITUIDA POR SEÇÃO PARA PREENCHER FRAME ETHERNET

	raw->ip.ver = 0x45;
	raw->ip.tos = 0x00;
	raw->ip.len = htons(size + sizeof(struct ip_hdr_s));
	raw->ip.id = htons(0x00);
	raw->ip.off = htons(0x00);
	raw->ip.ttl = 50;
	raw->ip.proto = 0xff;
	raw->ip.sum = htons(0x0000);

	/* fill source and destination addresses */

	/* calculate the IP checksum */
	/* raw->ip.sum = htons((~ipchksum((uint8_t *)&raw->ip) & 0xffff)); */

	/* fill payload data */


	/*
		SEÇÃO DE FILL DE DADOS DO TRABALHO

		pega tipo de msg
		muda hostname(pq?)
		se existir dados faz memcpy

	*/

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + size, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	return 0;
}
