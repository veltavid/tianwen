## 网络编程学习

#### 1.进程相关

1.如何循环生成n个子进程,并且这些子进程均为兄弟关系。

2.父子进程能否共享全局变量?

不能。

3.父子进程是否共享文件描述符,是否共享文件偏移量

都共享。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>

void do_something(int i);

int question2;//2
int file_fd;//3
int main()
{
    int i,pid,stat;//1
    char question3[10]="./test";//3
    file_fd=open(question3,O_RDWR | O_CREAT,S_IRWXU | S_IRWXG | S_IRWXO);
    //lseek(file_fd,5,SEEK_CUR);
    for(i=0;i<5;i++)
    {

        pid=fork();
        if(pid<0)
        {
            printf("fork error\n");
            break;
        }
        if(!pid)
        break;
        question2++;
    }
    if(!pid)
    do_something(i);
    else if(pid>0)
    {
        DIR* my_fd_dir;//3
        struct dirent* fd;//3
        char fds[100],content[30];//3
        my_fd_dir=opendir("/proc/self/fd");
        while(fd=readdir(my_fd_dir))
        {
            strcat(fds,fd->d_name);
            strcat(fds,"-");
        }
        fds[strlen(fds)-1]='\0';
        read(3,content,5);
        content[4]='\0';
        printf("father:pid==[%d],fpid==[%d],question2=%d,question3=%s,%s\n",getpid(),getppid(),question2,fds,content);
        for(i=0;i<5;i++)
        {
            pid=wait(&stat);
            printf("Process %d is terminated\n",pid);
        }
    }
    return 0;
}

void do_something(int i)
{
    DIR* my_fd_dir;//3
    struct dirent* fd;//3
    char fds[100],content[30];//3
    question2=0;//quetion2:check write
    my_fd_dir=opendir("/proc/self/fd");
    while(fd=readdir(my_fd_dir))
    {
        strcat(fds,fd->d_name);
        strcat(fds,"-");
    }
    fds[strlen(fds)-1]='\0';
    read(3,content,5);
    content[4]='\0';
    printf("child%d:pid==[%d],fpid==[%d],question2=%d,question3=%s,%s\n",i,getpid(),getppid(),question2,fds,content);
    //lseek(file_fd,0,SEEK_SET);
}
```

#### 2.信号量相关

1.电脑1秒种能数多少个数字？

```c
#include <unistd.h>
#include <signal.h>
#include <stdio.h>

void handle_alarm();
int amount=0;
int main()
{
    signal(SIGALRM,handle_alarm);
    alarm(1);
    while(1)
    {
        amount++;
        printf("%d\n",amount);
    }
    return 0;
}

void handle_alarm()
{
    //printf("Count %d numbers\n",amount);
    _exit(0);
}
```

2.使用settimer每隔1s输出一行字符串。

```c
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

void handle_alarm();
int main()
{
    int res;
    struct itimerval tick;
    signal(SIGALRM,handle_alarm);
    memset(&tick, 0, sizeof(tick));
    
    tick.it_value.tv_sec = 1; 
    tick.it_value.tv_usec = 0;
 
    tick.it_interval.tv_sec = 1;
    tick.it_interval.tv_usec = 0;
 
    res = setitimer(ITIMER_REAL, &tick, NULL);
    if(res)
    {
        printf("init timer failed\n");
        _exit(0);
    }
    while(1)
    pause();
    return 0;
}

void handle_alarm()
{
    printf("Hello world!\n");
}
```

3.设置阻塞信号集并把所有常规信号的未决状态打印至屏幕。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

void output_stat(sigset_t *pend_mask);

int main()
{
    sigset_t newmask,oldmask,pending;
	sigemptyset(&newmask);
  	sigaddset(&newmask,SIGINT);
    sigaddset(&newmask,SIGQUIT);
    sigaddset(&newmask,SIGTSTP);
    sigprocmask(SIG_BLOCK,&newmask,&oldmask);
    while(1)
    {
        if(sigpending(&pending))
        {
            printf("Get pending signal set failed\n");
            break;
        }
        output_stat(&pending);
        sleep(2);
    }
    return 0;
}

void output_stat(sigset_t *pend_mask)
{
    int i,signals[3]={2,3,20};
    char *signals_name[3]={"SIGINT","SIGQUIT","SIGTSTP"};
    for(i=0;i<3;i++)
    {
        if(sigismember(pend_mask,signals[i]))
        printf("%s:1\n",signals_name[i]);
        else
        printf("%s:0\n",signals_name[i]);
    }
}
```

4.使用sigaction函数注册信号捕捉函数，并使用这个程序验证信号不支持排队。

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

void handler2()
{
    printf("Signal does queue\n");
    _exit(0);
}

void handler()
{
    struct sigaction act;
    printf("The first time to capture SIGINT\n");
    act.sa_handler=handler2;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);
}

int main()
{
    sigset_t newmask,oldmask,pending;
    struct sigaction act;
	sigemptyset(&newmask);
  	sigaddset(&newmask,SIGINT);
    sigprocmask(SIG_BLOCK,&newmask,&oldmask);

    act.sa_handler=handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGINT, &act, 0);
    while(1)
    {
        sigpending(&pending);
        if(sigismember(&pending,SIGINT))
        break;
        else
        printf("Please press ctrl+c\n");
        sleep(1);
    }
    printf("Please press ctrl+c again in five seconds\n");
    sleep(5);
    sigprocmask(SIG_SETMASK,&oldmask,NULL);
    printf("Signal doesn't queue\n");
    return 0;
}
```

5.父进程创建三个子进程，然后让父进程捕获SIGCHLD信号完成对子进程的回收。

```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <wait.h>

void reap_child();
int main()
{
    int i,pid;
    sigset_t newmask,oldmask;
    signal(SIGCHLD,reap_child);
    sigemptyset(&newmask);
    sigaddset(&newmask,SIGCHLD);
    for(i=0;i<3;i++)
    {
        sigprocmask(SIG_BLOCK,&newmask,&oldmask);
        pid=fork();
        if(!pid)
        {
            setpgid(0,0);
            break;
        }
        sigprocmask(SIG_SETMASK,&oldmask,NULL);
    }
    if(!pid)
    {
        printf("I'm child%d[%d]\n",i+1,getpid());
    }
    else
    {
        while(1)
        sleep(1);
    }
    return 0;
}

void reap_child()
{
    int pid;
    int stat;
    printf("start reaping\n");
    while((pid=waitpid(-1,&stat,WNOHANG | WUNTRACED))>0)
    printf("Child[%d] is terminated\n",pid);
    printf("finish reaping\n");
}
```

