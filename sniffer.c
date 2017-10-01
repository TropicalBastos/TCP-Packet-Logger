#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <errno.h>

#define MAX_BUFFER 65535
#define IP_SIZE 16
#define IPv4 AF_INET

int sock_raw;
FILE *logfile;
int tcp=0, total=0, i, j;
struct sockaddr_in source, dest;

char* getIpFromDecimal(unsigned int ip)
{
    char *result = malloc(IP_SIZE);
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(result, IP_SIZE, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return result;      
}

void printIpHeader(unsigned char* buffer, int size){
    struct iphdr *iph = (struct iphdr*) buffer;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n\nIP HEADER\n");
    fprintf(logfile, "IP Version: %d\n", (unsigned int) iph->version);
    fprintf(logfile, "IP Header Length: %d in DWORDS\n", (unsigned int) iph->ihl);
    fprintf(logfile, "IP Type of Service: %d\n", (unsigned int) iph->tos);
    fprintf(logfile, "Source IP: %s\n", (char *) getIpFromDecimal((unsigned int) iph->saddr));
    fprintf(logfile, "Destination IP: %s\n", (char *) getIpFromDecimal((unsigned int) iph->daddr));
    fprintf(logfile, "\n");
}

void printTcpPacket(unsigned char* buffer, int size){
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr*) buffer;
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr*) (buffer + iphdrlen);
    
    printIpHeader(buffer, size);
    fprintf(logfile, "\n\n");
    fprintf(logfile, "***************************** TCP PACKET ******************************\n");
    fprintf(logfile, "\n");
    fprintf(logfile, "Source Port: %u\n", ntohs(tcp->source));
    fprintf(logfile, "Destination Port: %u\n", ntohs(tcp->dest));
    fprintf(logfile, "Sequence Number: %u\n", ntohl(tcp->seq));
    fprintf(logfile, "Acknowledge Number: %u\n", ntohl(tcp->ack_seq));
    fprintf(logfile, "\n########################################################################");
}

void processPacket(unsigned char *buffer, int size){
    //Lets get the IP header
    struct iphdr *iph = (struct iphdr*) buffer;
    total++;
    switch(iph->protocol){
        case 6: //TCP Protocol
            tcp++;
            printf("TCP packet sniffed! Analysing...\n");
            printTcpPacket(buffer, size);
        default:
            printf("Not a TCP packet, skipping...\n");     
    }
}

int main(int argc, char** argv){
    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char*) malloc(MAX_BUFFER);
    
    logfile = fopen("log.txt", "w");
    if(logfile == NULL) printf("Unable to create log file!\n");
    printf("Starting...\n");

    //raw socket for sniffing
    sock_raw = socket(IPv4, SOCK_RAW, IPPROTO_TCP);
    if(sock_raw < 0){
        printf("Could not create a socket...\n");
        printf("Error: %s\n", strerror(errno));
        return 1;
    }

    while(1){
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw, buffer, MAX_BUFFER, MSG_PEEK,
        &saddr, &saddr_size); //receive from socket and store in buffer

        if(data_size < 0){
            printf("Failed to get packets!\n");
            return 1;
        }

        processPacket(buffer, data_size);
    }

    close(sock_raw);
    printf("Finished");
    return 0;
}
