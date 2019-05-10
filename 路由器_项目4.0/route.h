#ifndef __ROUTE_H__
#define __ROUTE_H__

#define MAXARPS 160

typedef struct arp_msg
{
    unsigned char ip[4];
    unsigned char mac[6];
}ARPMSG;

ARPMSG arp_list[MAXARPS];
extern struct list_head head;

extern struct sockaddr_ll get_if_index(int sockfd,const char *name);
extern void printIp(unsigned char const *ip,char const *str);
extern void printf_help(void);
extern void read_ip_from_file(char const *path);
extern void save_set(const char *path);
extern void scan_arp(void);
extern void *route_pthread(void *arg);
extern void *cmd_print(void *arg);                                                           


#endif