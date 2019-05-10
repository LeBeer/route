#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include "get_interface.h"
#include "route.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "list.h"

char dst_mac[18] = "";
char src_mac[18] = "";

int arp_num = 0;  


typedef struct ip_inct
{
	unsigned char ip[4];
	struct list_head node;
}IPINCT;

struct list_head head;

struct sockaddr_ll get_if_index(int sockfd,const char *name)
{
    struct sockaddr_ll sll;                                                 //本地接口地址
    bzero(&sll,sizeof(sll));
    struct ifreq ifq;                                                       //使用ioctl 通过 某个网卡 发送出去
    strncpy(ifq.ifr_name,name,IFNAMSIZ);
    //printf("if_name = %s\n",name);
    if(ioctl(sockfd,SIOCGIFINDEX,&ifq) == -1)
    {
        perror("ioctl");
        close(sockfd);
        exit(-1);
    }
    sll.sll_ifindex = ifq.ifr_ifindex;
    return sll;
}

void printIp(unsigned char const *ip,char const *str)
{
    char ip_addr[16] = "";
    inet_ntop(AF_INET,(unsigned int *)ip,ip_addr,16);
    printf("%s = %s\n",str,ip_addr);
    return;
}

void printMac(unsigned char *mac,char const *str)
{
    char mac_addr[18] = "";
    sprintf(mac_addr,"%02x:%02X:%02x:%02x:%02X:%02x",\
        mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    printf("%s = %s\n",str,mac_addr);
    return;
}

void printf_help()
{
    printf("------------------------\n");
    printf("*01\thelp\t*终端控制\n");
    printf("*02\tmac\t*获取MAC\n");
    printf("*03\tarp\t*打印ARP表\n");
    printf("*04\tadd\t*添加过滤\n");
    printf("*05\tdel\t*删除过滤\n");
    printf("*06\tshow\t*打印过滤\n");
    printf("*06\tpath\t*PATH\n");
    printf("------------------------\n");
}
void read_ip_from_file(char const *path)
{
    char buf[2048] = "";
    int fd = open(path,O_RDONLY|O_CREAT,0777);
    int len = read(fd,buf,sizeof(buf));
    if(len < 0)
    {
        perror("read_file");
        return;
    }

    char *str = strtok(buf,"\n");
    if(str == NULL)
    {
        printf("配置文件无内容");
        return;
    }
    while(str != NULL)
    {
        int ip = inet_addr(str);
        IPINCT *pnew;
        pnew = malloc(sizeof(IPINCT));
        memcpy(pnew->ip,&ip,4);
        list_add(&pnew->node,&head);
        str =strtok(NULL,"\n");
    }
    close(fd);
    return;
}

void save_set(const char *path)
{
    int fd = open(path,O_WRONLY|O_TRUNC|O_CREAT,0777);

    IPINCT *pnew;
    list_for_each_entry(pnew,&head,node)
    {
        char ip[16] = "";
        inet_ntop(AF_INET,pnew->ip,ip,16);
        ip[strlen(ip)] = '\n';
        int len = write(fd,ip,strlen(ip));
        if(len < 0)
        {
            perror("write");
            return;
        }
    }
    printf("成功保存到配置文件\n");
    return;
}

void scan_arp(void)
{
    int i;
    printf("------------------------\n");
    printf("打印arp表\n");
    for(i = 0;i < arp_num;i++)
    {
        printIp(arp_list[i].ip,"ip");
        printIp(arp_list[i].mac,"mac");
    }
    printf("------------------------\n");


}

void *route_pthread(void *arg)
{
    int i,j;
              
    int if_num = get_interface_num();                                   //接口数量

    int sockfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(sockfd < 0)
    {
        perror("socket");
        return 0;
    }
    
    while(1)
    {
        unsigned char buf[1600] = "";
        bzero(&buf,sizeof(buf));
        int len = recvfrom(sockfd,buf,sizeof(buf),0,NULL,NULL);         //不断接受数据包
        if(len < 0)
        {
            perror("recvfrom");
            return 0;
        }

        sprintf(dst_mac, "%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
        sprintf(src_mac, "%02x:%02x:%02x:%02x:%02x:%02x", buf[0+6], buf[1+6], buf[2+6], buf[3+6], buf[4+6], buf[5+6]);
        unsigned short mac_type = ntohs(*(unsigned short *)(buf + 12));
        unsigned short macType = ntohs(*(unsigned short *)(buf+12));

        if(macType == 0x0800)                                           //IP数据包
        {
            int flag = 0;
            unsigned char *ip_buf = buf+14;
            unsigned char ipType = *(unsigned char *)(ip_buf+9);

            if(ipType == 1)                                             //ICMP协议
            {
                //printf("ICMP协议\n");
                char ip_src_addr[16] = "";
                char ip_dst_addr[16] = "";
                inet_ntop(AF_INET,(unsigned int *)(ip_buf + 12),ip_src_addr,16);
                inet_ntop(AF_INET,(unsigned int *)(ip_buf + 16),ip_dst_addr,16);
                //printf("IP:src_ip:%s--->(ip_but+16):%s\n",ip_src_addr,ip_dst_addr);

                for( i = 0; i < if_num; i++)                                                                    //遍历网络接口结构体
                {
                    if(memcmp(net_interface[i].ip,ip_buf+16,3) == 0)                                            //目的IP与某个网卡在同一网段
                    {
                        //printf("出现与路由器在同一网段的数据包\n");
                        char if_addr[16] = "";
                        inet_ntop(AF_INET,(unsigned int *)(net_interface[i].ip),if_addr, 16);
                        //printf("if_addr = %s\n",if_addr);
                    
                        for( j = 0; j < arp_num; j++)                                                           //遍历ARP表
                        {
                            if(memcmp((ip_buf +16),arp_list[j].ip,4) == 0)                                      //表中有与目的IP相同的IP
                            {

                                //puts("");
                                //printf("在ARP表中找到目的IP\n");
                                memcpy(buf+6,net_interface[i].mac,6);                                           //修改源MAC
                                memcpy(buf,arp_list[j].mac,6);                                                  //目的MAC改为目的IP的MAC转发出去

                                struct sockaddr_ll sll = get_if_index(sockfd,net_interface[i].name);
                                int ret = sendto(sockfd,buf,len,0,(struct sockaddr *)&sll,sizeof(sll));         //组好目的MAC 源MAC 将源MAC改为网卡MAC 
                                if (ret == -1)
                                {
                                    perror("ret");
                                }                                   
                                flag = 1;                                               //循环标志位置  
                                break;
                            } 
                        }
                        if(flag != 1)                                                   //ARP表中没有
                        {
                            //puts("");
                            //printf("没有ARP数据，准备广播ARP请求");
                          
                            //组mac头
                            unsigned char msg[2048] = "";
                            struct ether_header *ethHdr = (struct ether_header *)msg;
                            memset(ethHdr->ether_dhost,0xff,6);                         //目的mac
                            memcpy(ethHdr->ether_shost,net_interface[i].mac,6);
                            ethHdr->ether_type = htons(0x0806);                         //mac的协议类型

                            //组arp头
                            struct arphdr *arp_hdr = (struct arphdr *)(msg+14);         //跳过mac头
                            arp_hdr->ar_hrd = htons(1);                                 //硬件类型
                            arp_hdr->ar_pro = htons(0x0800);                            //软件协议类型
                            arp_hdr->ar_hln = 6;                                        //硬件地址长度
                            arp_hdr->ar_pln = 4;                                        //软件地址长度
                            arp_hdr->ar_op = htons(1);                                  //请求为1
                            memcpy(arp_hdr->__ar_sha,net_interface[i].mac,6);           //源mac
                            memcpy(arp_hdr->__ar_sip,net_interface[i].ip,4);            //源IP
                            memset(arp_hdr->__ar_tha,0,6);                              //arp的请求报文 目的mac为0
                            memcpy(arp_hdr->__ar_tip,(ip_buf + 16),4);                  //目的IP

                            //广播
                            struct sockaddr_ll sll = get_if_index(sockfd,net_interface[i].name);
                            sendto(sockfd,msg,42,0,(struct sockaddr *)&sll,sizeof(sll));                                              
                        }
                        break;
                    }
                }
            }    
        }
        
        else if(macType == 0x0806)                                                      //ARP数据包
        {
            unsigned short arrOp = ntohs(*(unsigned short *)(buf + 20));

            if(arrOp == 2)
            {
                unsigned char *src_mac_p = buf+6;
                unsigned char *src_ip_p = buf+28;

                int sign = 0;
                for(i = 0;i < arp_num; ++i)
                {
                    if(memcmp(src_ip_p,arp_list[1].ip,4) == 0)
                    {
                        sign = 1;
                        break;
                    }
                }
            if(sign != 1)
            {
                //puts("");
                //printf("收到ARP收到报文\n");
                char src_mac[18] = "";
                char src_ip[16] = "";
                //unsigned char *src_mac_p = buf+6;
                //unsigned char *src_ip_p = buf+28;

                //添加到ARP表
                memcpy(arp_list[arp_num].ip,src_ip_p,4);
                memcpy(arp_list[arp_num].mac,src_mac_p,6);
                inet_ntop(AF_INET,(int *)arp_list[arp_num].ip,src_ip,16);
                sprintf(src_mac,"%02x:%02x:%02x:%02x:%02x:%02x",\
                arp_list[arp_num].mac[0],arp_list[arp_num].mac[1],arp_list[arp_num].mac[2],\
                arp_list[arp_num].mac[3],arp_list[arp_num].mac[4],arp_list[arp_num].mac[5]);

                //printf("ip: %s\n",src_ip);
                //printf("mac: %s\n",src_mac);
                //puts("");
                arp_num++;
            }
            }
        }   
    }
    close(sockfd);
    return 0;
}

void *cmd_print(void *arg)
{
    char *path = (char *)arg;
    usleep(1000*10);

    printf_help();
    while(1)
    {
        printf("cmd<master>:");

        char cmd_help[128] = "";
        fgets(cmd_help,sizeof(cmd_help),stdin);
        int len = strlen(cmd_help);
        strtok(cmd_help," ");
        char *str = strtok(NULL,"\n");
        cmd_help[len - 1] = 0;
        if(strcmp(cmd_help,"help")== 0)
        {
            printf_help();
        }
        else if(strcmp(cmd_help,"mac") == 0)
        {
            printf("mac: %s --> %s\n", src_mac, dst_mac);

        }
        else if(strcmp(cmd_help,"arp") == 0)
        {
            scan_arp();
        }
        else if(strcmp(cmd_help,"add") == 0)
        {
            
            int sign = 0;            
            int ip = inet_addr(str);            
            IPINCT *pnew;            
            list_for_each_entry(pnew,&head,node)            
                if(memcmp(pnew->ip,&ip,4) == 0)            
                {
                    sign = 1;            
                    printf("链表中已有此IP\n");           
                    break;            
                }
            if(sign != 1)            
            {            
                pnew = malloc(sizeof(IPINCT));
                memcpy(pnew->ip,&ip,4);
                list_add(&pnew->node,&head);
                printf("成功添加\n");
            }
            puts("");
        }
        else if(strcmp(cmd_help,"del") == 0)
        {
            int sign = 0;
            int ip = inet_addr(str);
            IPINCT *pnew;
            list_for_each_entry(pnew,&head,node)
                if(memcmp(pnew->ip,&ip,4) == 0)
                {
                    sign = 1;
                    break;
                }
            if(sign == 1)
            {
                list_del(&pnew->node);
                printf("成功删除\n");
            }
            else
            {
                printf("没有此IP");
            }
            puts("");    
        }
        else if(strcmp(cmd_help,"show") == 0)
        {
            printf("------------------------\n");
            IPINCT *pnew;
            list_for_each_entry(pnew,&head,node)
                printIp(pnew->ip,"ip");
            printf("------------------------\n");
            
        }
        else if(strcmp(cmd_help,"path") == 0)
        {
            save_set(path);
        }
        else
        {
            printf("空空\n");
        }
        
    }
    return NULL;
}
