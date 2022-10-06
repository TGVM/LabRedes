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


struct host
{
	char name[HOSTNAMESIZE];
	char mac[6];
	bool active;
	time_t lastHeartbeat;
};

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6] =	{0x00, 0x00, 0x00, 0x22, 0x22, 0x22}; // trab não usa um valor definido de destino
char src_mac[6] =	{0x00, 0x00, 0x00, 0x33, 0x33, 0x33}; //trab não usa src_mac

char ifName[IFNAMSIZ];
struct host hosts[100];
char hostName[HOSTNAMESIZE];

int globalArgc;
char **globalArgv;
int subscribed_hosts_quantity;
bool start_received;


void timerCalculator()
{
	while(1) {
		time_t now;
		time(&now);
		for (int i = 0; i < subscribed_hosts_quantity; i++)
		{
			struct host *currHost = &hosts[i];
			if (!currHost->active)
			{
				continue;
			}
			if (difftime(now, currHost->lastHeartbeat) > 15)
			{
				currHost->active = false;
				printf("-> ");
				
				printf("Host ");
				
				printf("%s",currHost->name);
				
				printf(" timedout.\n");
			}
		}
		sleep(1);
	}
}

int sendRaw(char type, char *data[])					
{
	struct ifreq if_idx, if_mac, ifopts;
	struct sockaddr_ll socket_address;
	int sockfd, numbytes, size = 100;
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;

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

	uint8_t target_mac[6];
	memcpy(target_mac, bcast_mac, 6);

	//printf("\n218\n");

	if (type == TYPE_TALK || (type == TYPE_HEARTBEAT && start_received))
	{
		//target_mac = dst_mac;
		memcpy(target_mac, dst_mac, 6);
		start_received = false;
	}


	/* fill the Ethernet frame header */
	memcpy(raw->ethernet.dst_addr, target_mac, 6);		
	memcpy(raw->ethernet.src_addr, this_mac, 6);
	raw->ethernet.eth_type = htons(ETH_P_IP);

	/* Fill IP header data. Fill all fields and a zeroed CRC field, then update the CRC! */

	
	raw->ip.ver = 0x45;
	raw->ip.tos = 0x00;
	raw->ip.len = htons(size + sizeof(struct ip_hdr_s));
	raw->ip.id = htons(0x00);
	raw->ip.off = htons(0x00);
	raw->ip.ttl = 50;
	raw->ip.proto = 0xff;
	raw->ip.sum = htons(0x0000);
	
	/* fill source and destination addresses */

		//FALTA ISSO

	/* calculate the IP checksum */
	/* raw->ip.sum = htons((~ipchksum((uint8_t *)&raw->ip) & 0xffff)); */

	/* fill payload data */

	raw->ip.msg_type = type;
	strncpy(raw->ip.NomeHost, hostName, HOSTNAMESIZE);
	if(data != NULL) {
		memcpy(raw->ip.msg, data, sizeof(raw->ip.msg));
	}

	/* Send it.. */
	memcpy(socket_address.sll_addr, dst_mac, 6);
	if (sendto(sockfd, raw_buffer, sizeof(struct eth_hdr_s) + sizeof(struct ip_hdr_s) + size, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		printf("Send failed\n");


	return 0;
}


void * recvRaw(void * a)			
{
	struct ifreq ifopts;
	char ifName[IFNAMSIZ];
	int sockfd, numbytes;
	char *p;
	
	uint8_t raw_buffer[ETH_LEN];
	struct eth_frame_s *raw = (struct eth_frame_s *)&raw_buffer;
	
	/* Get interface name */
	if (globalArgc > 1)										
		strcpy(ifName, globalArgv[2]);						
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
		if (raw->ethernet.eth_type == ntohs(ETH_P_IP) && memcmp(raw->ethernet.src_addr, this_mac, 6)){		// muda parâmetros do if												//mudou parâmetros e conteúdo do if
			
			if(raw->ip.msg == TYPE_START){
				printf("Host ");
				
				printf("%s", raw->ip.NomeHost);

				// printf(", from MAC %x:%x:%x:%x:%x:%x ",
				// 	raw->ethernet.src_addr[0], raw->ethernet.src_addr[1], raw->ethernet.src_addr[2], raw->ethernet.src_addr[3], raw->ethernet.src_addr[4], raw->ethernet.src_addr[5]	
				// );

				//ARRUMAR END IP AQUI

				printf("logged in\n");

				struct host *currHost = &hosts[subscribed_hosts_quantity];
				memcpy(currHost->mac, raw->ethernet.src_addr,6);	//MUDAR STRUCT TROCAR MAC POR IP
				memcpy(currHost->name, raw->ip.host_name, 16);
				currHost->active = true;
				
				time(&(currHost->lastHeartbeat));
				subscribed_hosts_quantity++;
				memcpy(special_dst_mac, currHost->mac, 6);		//MUDAR STRUCT TROCAR MAC POR IP

				start_received = true;
				sendHeartbeat();

			} else if (raw->ip.msg == TYPE_HEARTBEAT) {
				bool achou = false;
				for (int i = 0; i < subscribed_hosts_quantity; i++)
				{
					struct host *currHost = &hosts[i];
					if (!currHost->active) continue;
					if (memcmp(currHost->mac, raw->ethernet.src_addr, 6) == 0)		//MUDAR PARA IP
					{
						achou = true;
						time(&(currHost->lastHeartbeat));
						break;
					}
				}
				if(!achou) {
					struct host *currHost = &hosts[subscribed_hosts_quantity];
					memcpy(currHost->mac, raw->ethernet.src_addr,6);		//MUDAR PARA IP
					memcpy(currHost->name, raw->ip.NomeHost, 6);
					currHost->active = true;
					
					time(&(currHost->lastHeartbeat));
					subscribed_hosts_quantity++;
					memcpy(dst_mac, currHost->mac, 6);		//MUDAR PARA IP
				}
			} else if (raw->ip.msg == TYPE_TALK) {
				printf("Message from ");
				
				printf("%s", raw->ip.NomeHost);

				printf(":");

				printf(" %s\n", raw->ip.msg);
			}

			//USAR COMO BASE \/

			// printf("IP packet, %d bytes - src ip: %d.%d.%d.%d dst ip: %d.%d.%d.%d proto: %d\n",
			// 	numbytes,
			// 	raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3],
			// 	raw->ip.dst[0], raw->ip.dst[1], raw->ip.dst[2], raw->ip.dst[3],
			// 	raw->ip.proto
			// );
			// if (raw->ip.proto == PROTO_UDP && raw->udp.dst_port == ntohs(DST_PORT)){
			// 	p = (char *)&raw->udp + ntohs(raw->udp.udp_len);
			// 	*p = '\0';
			// 	printf("src port: %d dst port: %d size: %d msg: %s", 
			// 	ntohs(raw->udp.src_port), ntohs(raw->udp.dst_port),
			// 	ntohs(raw->udp.udp_len), (char *)&raw->udp + sizeof(struct udp_hdr_s)
			// 	); 
			// }
			continue;
		}
				
		//printf("got a packet, %d bytes\n", numbytes);
	}
}
