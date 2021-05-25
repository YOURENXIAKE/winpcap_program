#include <stdio.h>
#include <stdlib.h>
#define HAVE_REMOTE
#include <pcap.h>
#ifndef PHEADER_H_INCLUDED
#define PHEADER_H_INCLUDED

#define ETHER_ADDR_LEN 6 /* ��̫����ַ */
#define ETHERTYPE_IP 0x0800 /* IP */
#define TCP_PROTOCAL 0x0600 /* TCP */
#define BUFFER_MAX_LENGTH 65536 /* ��������С */
#define true 1  /* ����1 */
#define false 0 /* ����0 */

/*
* ������̫��ͷ��IP��ַ��IPͷ�Լ�TCPͷ
*/
typedef struct ether_header {
    u_char ether_shost[ETHER_ADDR_LEN]; /* source ethernet address, 8 bytes */
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination ethernet addresss, 8 bytes */
    u_short ether_type;                 /* ethernet type, 16 bytes */
}ether_header;

/* IP��ַ */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPͷ */
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

/* TCPͷ */
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
    pcap_if_t* alldevs; // �豸��
    pcap_if_t* d; // �û�ѡ����豸
    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //��ӡ����Ļ�����
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* ��ͷ */
    const u_char * pkt_data; /* ������ */
    int res;

    /* Ѱ�������������� */
    char * location = "rpcap://172.20.155.203";

    if (pcap_findalldevs_ex(location, NULL , &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    printf("���������豸����:\n");
    /* ��ӡ���е������豸 */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // ��ӡ�����豸��
        if(d->description)
            printf(" (%s)\n", d->description); // ��ӡ�豸����
        else
            printf(" (No description available)\n");
    }

    /* ������������� */
    if (i == 0)
    {
        printf("\nNo interface found! Make sure Winpcap is installed.\n");
        return -1;
    }

    printf("��ѡ�������豸 (1-%d):", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* ȥ��������ѡ��������豸 */

    /* �򿪶�Ӧ�豸*/
    if((adhandle = pcap_open(d->name, /* �豸���� */
                 65536, /* ��ȡ���ĳ��ȣ��󣬾Ϳ��Ի�ȡ���еİ��������ݣ� */
                 PCAP_OPENFLAG_PROMISCUOUS, /* �ض�ģʽ */
                 1000, /* ��ʱ���� */
                 NULL,
                 errbuf /* ������Ϣ������ */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\n���ڼ��� %s...\n", d->description);

    pcap_freealldevs(alldevs); // ʩ�������豸�б�

    printf("ץȡ����IP��Ϣ���£�\n");
    /* ��ʼץ�� */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* ��ʱ��*/

        ether_header * eheader = (ether_header*)pkt_data; /* �õ���̫��ͷ */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* ����ֻ����IP���ݰ� */
            ip_header * ih = (ip_header*)(pkt_data+14); /* ͨ��14���õ�IPͷ */

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
pcap_if_t* alldevs; // �豸��
    pcap_if_t* d; // �û�ѡ����豸
    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //��ӡ����Ļ�����
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* ��ͷ */
    const u_char * pkt_data; /* ������ */
    int res;

    /* Ѱ�������������� */
    char * location = "rpcap://172.20.155.203";

    if (pcap_findalldevs_ex(location, NULL , &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    printf("���������豸����:\n");
    /* ��ӡ���е������豸 */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // ��ӡ�����豸��
        if(d->description)
            printf(" (%s)\n", d->description); // ��ӡ�豸����
        else
            printf(" (No description available)\n");
    }

    /* ������������� */
    if (i == 0)
    {
        printf("\nNo interface found! Make sure Winpcap is installed.\n");
        return -1;
    }

    printf("��ѡ�������豸 (1-%d):", i);
    scanf("%d", &inum);

    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* ȥ��������ѡ��������豸 */

    /* �򿪶�Ӧ�豸*/
    if((adhandle = pcap_open(d->name, /* �豸���� */
                 65536, /* ��ȡ���ĳ��ȣ��󣬾Ϳ��Ի�ȡ���еİ��������ݣ� */
                 PCAP_OPENFLAG_PROMISCUOUS, /* �ض�ģʽ */
                 1000, /* ��ʱ���� */
                 NULL,
                 errbuf /* ������Ϣ������ */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\n���ڼ��� %s...\n", d->description);

    pcap_freealldevs(alldevs); // ʩ�������豸�б�

    printf("ץȡ����HTTP�������£�\n");
    /* ��ʼץ�� */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* ��ʱ��*/

        ether_header * eheader = (ether_header*)pkt_data; /* �õ���̫��ͷ */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* ����ֻ����IP���ݰ� */
            ip_header * ih = (ip_header*)(pkt_data+14); /* ͨ��14���õ�IPͷ */

            if(ih->proto == htons(TCP_PROTOCAL)) { /* ���ǽ�һ��ֻ����TCP�� */
                int ip_len = ntohs(ih->tlen); /* �ȵõ�IP���� */

                int find_http = false;
                char* ip_pkt_data = (char*)ih;
                int n = 0;
                char buffer[BUFFER_MAX_LENGTH];
                int bufsize = 0;

                for(; n<ip_len; n++)
                {
                    /* Get����Post���� */
                    if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
                   || (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
                            find_http = true;

                    /* HTTP��Ӧ */
                    if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
                           find_http = true;

                    /* ����ҵ���HTTP */
                    if(find_http)
                    {   //printf("%c",ip_pkt_data[n]);
                        buffer[bufsize] = ip_pkt_data[n]; /* ��������ץȡ��HTTP���� */
                        bufsize ++;
                    }
                }
                /* ��ӡһ�� */
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
    pcap_if_t* alldevs; // �豸��
    pcap_if_t* d; // �û�ѡ����豸
    pcap_t* adhandle;

    char errbuf[PCAP_ERRBUF_SIZE]; //��ӡ����Ļ�����
    int i=0;
    int inum;

    struct pcap_pkthdr *pheader; /* ��ͷ */
    const u_char * pkt_data; /* ������ */
    int res;

    /* Ѱ�������������� */
    //char * location = "rpcap://";
    //char * location = "rpcap://172.20.155.203";
    char * location = "rpcap://172.20.15.3";

    if (pcap_findalldevs_ex(location, NULL , &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    printf("���������豸����:\n");
    /* ��ӡ���е������豸 */
    for(d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name); // ��ӡ�����豸��
        if(d->description)
            printf(" (%s)\n", d->description); // ��ӡ�豸����
        else
            printf(" (No description available)\n");
    }

    /* ������������� */
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

    for(d=alldevs, i=0; i < inum-1; d=d->next, i++); /* ȥ��������ѡ��������豸 */

    /* �򿪶�Ӧ�豸*/
    if((adhandle = pcap_open(d->name, /* �豸���� */
                 65536, /* ��ȡ���ĳ��ȣ��󣬾Ϳ��Ի�ȡ���еİ��������ݣ� */
                 PCAP_OPENFLAG_PROMISCUOUS, /* �ض�ģʽ */
                 1000, /* ��ʱ���� */
                 NULL,
                 errbuf /* ������Ϣ������ */
                 )) == NULL)
                 {
                     fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Winpcap\n",
                             d->description);
                     return -1;
                 }

    printf("\n���ڼ��� %s...\n", d->description);

    pcap_freealldevs(alldevs); // ʩ�������豸�б�

    printf("�û����ʵ���ַ������ļ����£�\n");
    /* ��ʼץ�� */
    while((res = pcap_next_ex(adhandle, &pheader, &pkt_data)) >= 0) {

        if(res == 0)
            continue; /* ��ʱ��*/

        ether_header * eheader = (ether_header*)pkt_data; /* �õ���̫��ͷ */
        if(eheader->ether_type == htons(ETHERTYPE_IP)) { /* ����ֻ����IP���ݰ� */
            ip_header * ih = (ip_header*)(pkt_data+14); /* ͨ��14���õ�IPͷ */

            if(ih->proto == htons(TCP_PROTOCAL)) { /* ���ǽ�һ��ֻ����TCP�� */
                int ip_len = ntohs(ih->tlen); /* �ȵõ�IP���� */

                int find_http = false;
                char* ip_pkt_data = (char*)ih;
                int n = 0;
                char buffer[BUFFER_MAX_LENGTH];
                int bufsize = 0;

                for(; n<ip_len; n++)
                {
                    /* Get����Post���� */
                    if(!find_http && ((n+3<ip_len && strncmp(ip_pkt_data+n,"GET",strlen("GET")) ==0 )
                   || (n+4<ip_len && strncmp(ip_pkt_data+n,"POST",strlen("POST")) == 0)) )
                            find_http = true;

                    /* HTTP��Ӧ */
                    if(!find_http && n+8<ip_len && strncmp(ip_pkt_data+n,"HTTP/1.1",strlen("HTTP/1.1"))==0)
                           find_http = true;

                    /* ����ҵ���HTTP */
                    if(find_http)
                    {
                        buffer[bufsize] = ip_pkt_data[n]; /* ��������ץȡ��HTTP���� */
                        bufsize ++;
                    }
                }
                /* ��ӡ */
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
    printf("�����������ʲô��0:ץȡIP��Ϣ;1:ץȡHTTP����;2:ץȡ���������������վ����Դ\n");
    printf("����ѡ��Ϊ:");
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
        printf("��������ַ����Ϸ���������0~2֮���������\n");
        goto FALL;
    }
}
