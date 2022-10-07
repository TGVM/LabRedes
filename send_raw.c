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
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>

#define HOSTNAMESIZE 32

struct host
{
	char name[HOSTNAMESIZE];
	char mac[6];
	char ip[4];
	bool active;
	time_t lastHeartbeat;
};

char this_mac[6];
char bcast_mac[6] =	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
char dst_mac[6];

uint8_t this_ip[4];
uint8_t bcast_ip[4] = {255, 255, 255, 255};
uint8_t dst_ip[4];


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

void printHosts() {
	printf("\n=== Host List ===\n\n");

	for (int i = 0; i < subscribed_hosts_quantity; i++)
	{
		struct host *currHost = &hosts[i];
		if (!currHost->active) continue;
		
		printf("Host Name: ");

		printf("%s",currHost->name);
		
		printf("\nAt ip: %d.%d.%d.%d\n\n",
			currHost->ip[0], currHost->ip[1], currHost->ip[2], currHost->ip[3]
		);
		//VER SE ESTÁ FUNCIONANDO

		// printf("\nAt MAC: %x:%x:%x:%x:%x:%x\n\n",
		// 	currHost->mac[0], currHost->mac[1], currHost->mac[2], currHost->mac[3], currHost->mac[4], currHost->mac[5]
		// );
		//FAZER ESSE PRINT /\ PRA IP
	}
	printf("=================\n");
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

	//this_ip???

	struct ifreq ifr;
	int n;
    n = socket(AF_INET, SOCK_DGRAM, 0);
    //Type of address to retrieve - IPv4 IP address
    ifr.ifr_addr.sa_family = AF_INET;
    //Copy the interface name in the ifreq structure
    // strncpy(ifr.ifr_name , array , IFNAMSIZ - 1);
    // ioctl(n, SIOCGIFADDR, &ifr);
    close(n);
    //display result
    //printf("IP Address is %s - %s\n" , array , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr)


	memcpy(this_ip, inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr), 6);

	/* End of configuration. Now we can send data using raw sockets. */


	/* To send data (in this case we will cook an ARP packet and broadcast it =])... */

	uint8_t target_mac[6];
	uint8_t target_ip[4];
	memcpy(target_mac, bcast_mac, 6);
	memcpy(target_ip, bcast_ip, 4);

	//printf("\n218\n");

	if (type == TYPE_TALK || (type == TYPE_HEARTBEAT && start_received))
	{
		//target_mac = dst_mac;
		memcpy(target_mac, dst_mac, 6);
		memcpy(target_ip, dst_ip, 4);
		start_received = false;
	}


	/* fill the Ethernet frame header */
	memcpy(raw->ethernet.dst_addr, target_mac, 6);		
	memcpy(raw->ethernet.src_addr, this_mac, 6);
	raw->ethernet.eth_type = htons(ETHER_TYPE);

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
	//raw->ip.dst = ;
	//raw->ip.src = this_ip; //(?)
	memcpy(raw->ip.src, this_ip, 4);

	/* calculate the IP checksum */
	/* raw->ip.sum = htons((~ipchksum((uint8_t *)&raw->ip) & 0xffff)); */

	/* fill payload data */

	raw->ip.msg_type = type;
	strncpy(raw->ip.NomeHost, hostName, HOSTNAMESIZE);
	if(data != NULL) {
		memcpy(raw->ip.msg, data, sizeof(raw->ip.msg));
	}

	/* Send it.. */
	memcpy(socket_address.sll_addr, target_mac, 6);
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
	if (globalArgc > 2)										
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
		if (raw->ethernet.eth_type == ntohs(ETHER_TYPE) && memcmp(raw->ethernet.src_addr, this_mac, 6)){		
			
			if(memcmp(raw->ethernet.dst_addr, this_mac, 6)!=0 && memcmp(raw->ethernet.dst_addr, bcast_mac, 6)!=0) {
				continue;
			}
			
			if(raw->ip.msg_type == TYPE_START){
				printf("Host ");
				
				printf("%s", raw->ip.NomeHost);

				

				printf(", from ip %d.%d.%d.%d ",
				raw->ip.src[0], raw->ip.src[1], raw->ip.src[2], raw->ip.src[3]
				);



				printf("logged in\n");

				struct host *currHost = &hosts[subscribed_hosts_quantity];
				memcpy(currHost->mac, raw->ethernet.src_addr,6);	
				memcpy(currHost->ip, raw->ip.src, 4);
				memcpy(currHost->name, raw->ip.NomeHost, 16);
				currHost->active = true;
				
				time(&(currHost->lastHeartbeat));
				subscribed_hosts_quantity++;
				
				start_received = true;
				sendHeartbeat();

			} else if (raw->ip.msg_type == TYPE_HEARTBEAT) {
				bool achou = false;
				for (int i = 0; i < subscribed_hosts_quantity; i++)
				{
					struct host *currHost = &hosts[i];
					if (!currHost->active) continue;
					if (memcmp(currHost->mac, raw->ethernet.src_addr, 6) == 0)		
					{
						achou = true;
						time(&(currHost->lastHeartbeat));
						break;
					}
				}
				if(!achou) {
					struct host *currHost = &hosts[subscribed_hosts_quantity];
					memcpy(currHost->mac, raw->ethernet.src_addr,6);		
					memcpy(currHost->ip, raw->ip.src,6);
					memcpy(currHost->name, raw->ip.NomeHost, 16);
					currHost->active = true;
					
					time(&(currHost->lastHeartbeat));
					subscribed_hosts_quantity++;
					memcpy(dst_mac, currHost->mac, 6);		
					memcpy(dst_ip, currHost->ip, 4);
				}
			} else if (raw->ip.msg_type == TYPE_TALK) {
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

int sendStart() {
	return sendRaw(TYPE_START, NULL);
}

int sendHeartbeat() {
	return sendRaw(TYPE_HEARTBEAT, NULL);
}


int sendTalk(char *data) {
	return sendRaw(TYPE_TALK, data);
}

void * heartBeater(void * a) {
	while(1) {
		sleep(5);
		sendHeartbeat();
	}
}

int main(int argc, char *argv[])
{
	subscribed_hosts_quantity = 0;
	start_received = false;
	globalArgv = argv;
	globalArgc = argc;
	pthread_t receive_th;
	pthread_t timer_th;
	pthread_t heartbeat_th;


	if (argc > 1) {
		strcpy(hostName, argv[1]);
	}
	else {
		gethostname(hostName, HOSTNAMESIZE);
	}
	printf("Logged as: ");
	
	printf("%s",hostName);

	/* Get interface name */
	if (argc > 2) {
		strcpy(ifName, argv[2]);
	}
	else {
		strcpy(ifName, DEFAULT_IF);
	}
	printf(" using interface %s\n",ifName);

	/* Create receiver thread */
	pthread_create(&receive_th, NULL, recvRaw, NULL);
	pthread_create(&timer_th, NULL, timerCalculator, NULL);
	pthread_create(&heartbeat_th, NULL, heartBeater, NULL);
	
	/* Sends Start message */
	sendStart();

	sleep(3);
	/* Starts input loop */
	while(1) {
		bool sair = false;
		while(!sair) {
			printf("Select an option:\n    1 - List Hosts\n    2 - Send Message\n    3 - Exit\n");
			
			char entry;
			entry = getc(stdin);
			
			// Flush 
			int c;
			while ((c = getchar()) != '\n' && c != EOF);
			
			switch(entry) {
				case '1':
					printHosts();
					break;
				case '2':
					sair = true;
					break;
				case '3':
					return 0;
			}
		}


		char target_host_name[16];
		
		printf("Type target ");
		
		printf("hostname");
		
		printf(" to message: \n");

		fgets(target_host_name, 16, stdin);
		fflush(stdin);

		for(int i = 0; i < 16; i++) {
			if(target_host_name[i]=='\0') {
				target_host_name[i-1] = '\0';
				break;
			}
		}

		//pega mac da tabela e coloca na var global //MUDAR PARA IP
		for (int i = 0; i < subscribed_hosts_quantity; i++)
		{
			struct host *currHost = &hosts[i];
			if (!currHost->active) continue;
			
			

			if (strcmp(currHost->name, target_host_name) == 0)
			{
				memcpy(dst_mac, currHost->mac, 6);	 
				memcpy(dst_ip, currHost->ip, 4);
				break;
			}
		}
		
		char sending_message[64];

		printf("Saying to ");
		
		printf("%s", target_host_name);

		printf(": \n");

		fgets(sending_message, 128, stdin);
		fflush(stdin);

		sendTalk(sending_message);
	}
}