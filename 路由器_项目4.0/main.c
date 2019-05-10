#include <stdio.h>
#include <pthread.h>
#include "route.h"
#include "list.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
	{
		printf("请输入ip配置文件名\n");
		printf("sudo ./route file_path\n");
		return -1;
	}
    INIT_LIST_HEAD(&head);
    read_ip_from_file(argv[1]);
    getinterface();                     //调用获区接口信息函数
    pthread_t tid1;                     //创建用于接收数据包的线程
    int ret = pthread_create(&tid1,NULL,route_pthread,NULL);
    if(ret < 0)
    {
        perror("pthread_create");
        return 0;
    }

    pthread_t tid2;                     //创建用于接收打印命令的线程
    ret = pthread_create(&tid2,NULL,cmd_print,argv[1]);
    if(ret < 0)
    {
        perror("pthread_create");
        return -1;
    }

    pthread_join(tid1,NULL);            //线程等待
    pthread_join(tid2,NULL);            //线程等待
    return 0;
}
