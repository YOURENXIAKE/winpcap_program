#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>
#ifndef PHEADER_H_INCLUDED
#define PHEADER_H_INCLUDED

#define ETHER_ADDR_LEN 6 /* 以太网地址 */
#define ETHERTYPE_IP 0x0800 /* IP */
#define TCP_PROTOCAL 0x0600 /* TCP */
#define BUFFER_MAX_LENGTH 65536 /* 缓冲区大小 */
#define true 1  /* 布尔1 */
#define false 0 /* 布尔0 */

/*
* 定义以太网头、IP地址、IP头以及TCP头
*/
typedef struct ether_header {
    u_char ether_shost[ETHER_ADDR_LEN]; /* source ethernet address, 8 bytes */
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet addresss, 8 bytes */
    u_short ether_type;                 /* ethernet type, 16 bytes */
}ether_header;

/* IP地址 */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IP头 */
typedef struct ip_header {
    u_char ver_ihl;         /* version and ip header length */
    u_char tos;             /* type of service */
    u_short tlen;           /* total length */
    u_short identification; /* identification */
    u_short flags_fo;       // flags and fragment offset
    u_char ttl;             /* time to live */
    u_char proto;           /* protocol */
    u_short crc;            /* header checksum */
    ip_address saddr;       /* source address */
    ip_address daddr;       /* destination address */
    u_int op_pad;           /* option and padding */
}ip_header;

/* TCP头 */
typedef struct tcp_header {
    u_short th_sport;         /* source port */
    u_short th_dport;         /* destination port */
    u_int th_seq;             /* sequence number */
    u_int th_ack;             /* acknowledgement number */
    u_short th_len_resv_code; /* datagram length and reserved code */
    u_short th_window;        /* window */
    u_short th_sum;           /* checksum */
    u_short th_urp;           /* urgent pointer */
}tcp_header;

#endif // PHEADER_H_INCLUDED

void captureIpInformation(){
    pcap_if_t* alldevs; // 设备表
    pcap_if_t* d; // 用户选择的设备
    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //打印错误的缓冲区
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* 包头 */
    const u_char * pkt_data; /* 包数据 */
    int res;

    /* 寻找网卡错误处理函数 */
    char * location = "rpcap://172.20.155.203";

    if (pcap_findalldevs_ex(location, NULL , &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    printf("所有网卡设备如下:\n");
    /* 打印所有的网卡设备 */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // 打印网卡设备名
        if(d->description)
            printf(" (%s)\n", d->description); // 打印设备描述
        else
            printf(" (No description available)\n");
    }

    /* 处理无网卡情况 */
    if (i == 0)
    {
        printf("\nNo interface found! Make sure Winpcap is installed.\n");
        return -1;
    }

    printf("请选择网卡设备 (1-%d):", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* 去处理我们选择的网卡设备 */

    /* 打开对应设备*/
    if((adhandle = pcap_open(d->name, /* 设备名字 */
                 65536, /* 获取包的长度（大，就可以获取所有的包数据内容） */
                 PCAP_OPENFLAG_PROMISCUOUS, /* 特定模式 */
                 1000, /* 超时处理 */
                 NULL,
                 errbuf /* 错误信息缓冲区 */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\n正在监听 %s...\n", d->description);

    pcap_freealldevs(alldevs); // 施放网卡设备列表

    printf("抓取到的IP信息如下：\n");
    /* 开始抓包 */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* 超时了*/

        ether_header * eheader = (ether_header*)pkt_data; /* 得到以太网头 */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* 我们只处理IP数据包 */
            ip_header * ih = (ip_header*)(pkt_data+14); /* 通过14，得到IP头 */

            printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
            ih->saddr.byte1,
            ih->saddr.byte2,
            ih->saddr.byte3,
            ih->saddr.byte4,
            ih->daddr.byte1,
            ih->daddr.byte2,
            ih->daddr.byte3,
            ih->daddr.byte4
            );
        }
    }
    return 0;
}

void captureHTTPMessage(){
pcap_if_t* alldevs; // 设备表
    pcap_if_t* d; // 用户选择的设备
    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //打印错误的缓冲区
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* 包头 */
    const u_char * pkt_data; /* 包数据 */
    int res;

    /* 寻找网卡错误处理函数 */
    char * location = "rpcap://172.20.155.203";

    if (pcap_findalldevs_ex(location, NULL , &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    printf("所有网卡设备如下:\n");
    /* 打印所有的网卡设备 */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // 打印网卡设备名
        if(d->description)
            printf(" (%s)\n", d->description); // 打印设备描述
        else
            printf(" (No description available)\n");
    }

    /* 处理无网卡情况 */
    if (i == 0)
    {
        printf("\nNo interface found! Make sure Winpcap is installed.\n");
        return -1;
    }

    printf("请选择网卡设备 (1-%d):", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* 去处理我们选择的网卡设备 */

    /* 打开对应设备*/
    if((adhandle = pcap_open(d->name, /* 设备名字 */
                 65536, /* 获取包的长度（大，就可以获取所有的包数据内容） */
                 PCAP_OPENFLAG_PROMISCUOUS, /* 特定模式 */
                 1000, /* 超时处理 */
                 NULL,
                 errbuf /* 错误信息缓冲区 */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\n正在监听 %s...\n", d->description);

    pcap_freealldevs(alldevs); // 施放网卡设备列表

    printf("抓取到的HTTP报文如下：\n");
    /* 开始抓包 */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* 超时了*/

        ether_header * eheader = (ether_header*)pkt_data; /* 得到以太网头 */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* 我们只处理IP数据包 */
            ip_header * ih = (ip_header*)(pkt_data+14); /* 通过14，得到IP头 */

            if(ih->proto == htons(TCP_PROTOCAL)) { /* 我们进一步只处理TCP包 */
                int ip_len = ntohs(ih->tlen); /* 先得到IP长度 */

                int find_http = false;
                char* ip_pkt_data = (char*)ih;
                int n = 0;
                char buffer[BUFFER_MAX_LENGTH];
                int bufsize = 0;

                for(; n<ip_len; n++)
                {
                    /* Get或者Post请求 */
                    if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
                   || (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
                            find_http = true;

                    /* HTTP响应 */
                    if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
                           find_http = true;

                    /* 如果找到了HTTP */
                    if(find_http)
                    {   //printf("%c",ip_pkt_data[n]);
                        buffer[bufsize] = ip_pkt_data[n]; /* 拷贝我们抓取的HTTP数据 */
                        bufsize ++;
                    }
                }
                /* 打印一波 */
                    if(find_http) {
                        printf("%s\n", buffer);
                        printf("\n*************EL PSY CONGROO************\n\n");
                    }
            }
        }
    }

    return 0;
}

void captureWebsitesAndResources(){
    pcap_if_t* alldevs; // 设备表
    pcap_if_t* d; // 用户选择的设备
    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //打印错误的缓冲区
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* 包头 */
    const u_char * pkt_data; /* 包数据 */
    int res;

    /* 寻找网卡错误处理函数 */
    //char * location = "rpcap://";
    //char * location = "rpcap://172.20.155.203";
    char * location = "rpcap://172.20.15.3";

    if (pcap_findalldevs_ex(location, NULL , &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    printf("所有网卡设备如下:\n");
    /* 打印所有的网卡设备 */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // 打印网卡设备名
        if(d->description)
            printf(" (%s)\n", d->description); // 打印设备描述
        else
            printf(" (No description available)\n");
    }

    /* 处理无网卡情况 */
    if (i == 0)
    {
        printf("\nNo interface found! Make sure Winpcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* 去处理我们选择的网卡设备 */

    /* 打开对应设备*/
    if((adhandle = pcap_open(d->name, /* 设备名字 */
                 65536, /* 获取包的长度（大，就可以获取所有的包数据内容） */
                 PCAP_OPENFLAG_PROMISCUOUS, /* 特定模式 */
                 1000, /* 超时处理 */
                 NULL,
                 errbuf /* 错误信息缓冲区 */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\n正在监听 %s...\n", d->description);

    pcap_freealldevs(alldevs); // 施放网卡设备列表

    printf("用户访问的网址及相关文件如下：\n");
    /* 开始抓包 */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* 超时了*/

        ether_header * eheader = (ether_header*)pkt_data; /* 得到以太网头 */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* 我们只处理IP数据包 */
            ip_header * ih = (ip_header*)(pkt_data+14); /* 通过14，得到IP头 */

            if(ih->proto == htons(TCP_PROTOCAL)) { /* 我们进一步只处理TCP包 */
                int ip_len = ntohs(ih->tlen); /* 先得到IP长度 */

                int find_http = false;
                char* ip_pkt_data = (char*)ih;
                int n = 0;
                char buffer[BUFFER_MAX_LENGTH];
                int bufsize = 0;

                for(; n<ip_len; n++)
                {
                    /* Get或者Post请求 */
                    if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
                   || (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
                            find_http = true;

                    /* HTTP响应 */
                    if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
                           find_http = true;

                    /* 如果找到了HTTP */
                    if(find_http)
                    {
                        buffer[bufsize] = ip_pkt_data[n]; /* 拷贝我们抓取的HTTP数据 */
                        bufsize ++;
                    }
                }
                /* 打印 */
                    if(find_http) {
                        char cap_http[10000];
                        int point = 0;
                        buffer[bufsize] = '\0';
                        int length = 0;

                        if(buffer[0] != 'G') continue;
                        for(int i = 0; buffer[i] != '\n'; i++){
                            length = i;
                        }
                        length += 8;
                        for(;buffer[length] != '\n';length++){
                                cap_http[point] = buffer[length];
                                point+=1;
                        }
                        point = point-1;
                        for(i = 4 ;buffer[i] != ' ';i++){
                                cap_http[point] = buffer[i];
                                point +=1;
                        }
                        cap_http[point] = '\0';
                        printf("%s\n", cap_http);
                        printf("\n*************EL PSY CONGROO************\n\n");
              }
            }
        }
    }
    return 0;
}

int main()
{
    int choice = 0;
FALL:
    printf("请输入您想干什么？0:抓取IP信息;1:抓取HTTP报文;2:抓取主机正在浏览的网站及资源\n");
    printf("您的选择为:");
    scanf("%d",&choice);
    switch(choice){
    case 0 :
        captureIpInformation();
        break;
    case 1:
        captureHTTPMessage();
        break;
    case 2:
        captureWebsitesAndResources();
        break;
    default:
        printf("您输入的字符不合法！请输入0~2之间的整数！\n");
        goto FALL;
    }
}
