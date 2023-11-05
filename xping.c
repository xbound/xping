/****************************************************************
 *	GNU General Public License Version 3 or later (GPL3+)	*
 *		https://www.gnu.org/licenses/gpl-3.0.txt	*
 ****************************************************************/
#define _GNU_SOURCE
char license[]={
#ifdef DOC_BIN
#include "license_bin"
	,'\n',0x00
#else 
	"https://www.gnu.org/licenses/gpl-3.0.txt\n"
#endif
};
#include <stdio.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/select.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/epoll.h>
//#define RELEASE
//#define USE_EPOLL_PWAIT2 //suggested if you kernel version>=5.11
#define ERR_LSEEK ((off_t)-1)
#define waitf(uaddr,val) syscall(SYS_futex,uaddr,FUTEX_WAIT,val,NULL,NULL,0)
//#define waitf(uaddr,val) (-1)
//#define wakef(uaddr,val) (-1)
#define wakef(uaddr,val) syscall(SYS_futex,uaddr,FUTEX_WAKE,val,NULL,NULL,0)
#define MAX_NPROCESS 16
#define MAX_HIDDEN_ERRORS 128
#define TSTACK_SIZE (8192)
#define INPUT_SIZE 1024
struct argandret{
	long id,tid;
	unsigned long sent,sent_ok,sent_size,aborted,nerror;
	long end;
	uint32_t mutex;
	uint16_t icmp_seqc,icmp_idc;
};
enum vlmode {INC,RAND,DEC,FIX} icmp_seqmode=INC,icmp_idmode=FIX;
enum {TYPE_AUTO,TYPE_RAW,TYPE_DGRAM} sock_type=TYPE_AUTO;
enum {CHECK_AUTO,CHECK_SELECT,CHECK_EPOLL,CHECK_NO,CHECK_NONE} check_mode=CHECK_NONE;
enum __proto {P_NONE,P_ETHER,P_IP,P_IP6,P_ICMP,P_ICMP6,P_UDP} base_proto=P_NONE;
enum __proto upper_proto=P_ICMP;
struct timespec ts;
//int sock_domain,sock_protocol;
uint16_t icmp_seq0=0,icmp_type=ICMP_ECHO,icmp_echoid=0;
uint16_t sin_port=0;
struct in_addr ip_addr;
char sleep_between_sents=0,running,count_written=0,update_ok=1;
char *target=NULL,*bind_device=NULL,*data_from_file=NULL,*tstack;
size_t packlen,data_size=0,sent_sum=0,sent_sum_ok=0,count=0,sent_sum_size=0,aborted_sum=0,nerror_sum=0;
void (*phdr[MAX_NPROCESS])(void *s,size_t offset,struct argandret *aar);
size_t (*fhdr[MAX_NPROCESS])(void *s,size_t offset,struct argandret *aar);
size_t offsets[MAX_NPROCESS];
char read_stdin_stack[TSTACK_SIZE];
char input[INPUT_SIZE];//read_stdin
char input1[INPUT_SIZE];//main
char input2[INPUT_SIZE];//read_stdin
char lastcmd[INPUT_SIZE];
int hidden_errors[MAX_HIDDEN_ERRORS];
long nhidden_errors=0;
long nthreads=1,cthreads,rthreads=0;
struct argandret *targ;
int pid,ctout=-1;
volatile uint32_t smutex=0;
unsigned int do_alarm=0;
pthread_mutex_t gmutex;
struct timespec cts;
//struct timeval ctv;
struct timespec *pcts=NULL;
//struct timeval *pctv=NULL;

//#define epoll_create(x) (-1)
//#define epoll_ctl(x,y,z,t) (-1)
//#define clone(x,y,z,t) (-1)
//#define malloc(x) NULL
const char *bfname(const char *path){
	if(path[0]=='/'&&path[1]=='\0')return path;
	path=strrchr(path,'/');
	return path+1;
}
int dat2spec(const char *restrict a,struct timespec *restrict spec){
	unsigned long i,n,r0;
	i=0;n=0;
	while(*a){
		if(*a<='9'&&*a>='0'){
			i=i*10+(*a-'0');
			++a;
		}else if(*a=='.'){
			break;
		}else return 0;
	}
	if(!*a){
	spec->tv_sec=i;
	spec->tv_nsec=0;
		return 1;
	}
	r0=1000000000l/10l;
	while(*++a){
		if(*a<='9'&&*a>='0'){
			n+=(*a-'0')*r0;
			r0/=10;
		}else return 0;
	}
	spec->tv_sec=i;
	spec->tv_nsec=n;
return 2;
}
char *b2hu(size_t byte,char *out){
	size_t n[5];
	size_t rate=40,i=0;
	if(byte==0){
		strcpy(out,"0B");
		return out;
	}
	while(i<5){
	//	printf("%ld\n",byte);
		n[i]=(byte>>rate);
		byte%=(1lu<<rate);
	//	printf("%ld\n",n[i]);
		rate-=10;
		++i;
	}
	sprintf(out,"%zuT %zuG %zuM %zuK %zuB",n[0],n[1],n[2],n[3],n[4]);
	i=0;
		while((out[i]<'1'||out[i]>'9')&&out[i])++i;
	return out+i;
}
uint16_t cksum(const void *s,size_t n){
	uint32_t sum=0;
	const uint16_t *p=(const uint16_t *)s;
	while(n>1){
		sum+=*p++;
		n-=2;
	}
	if(n)sum+=(uint16_t)*(uint8_t *)p;
	sum=(sum>>16)+(sum&0xffff);
	return ~sum;
}
int sockerr(int fd){
	socklen_t optlen;
	optlen=sizeof(fd);
	getsockopt(fd,SOL_SOCKET,SO_ERROR,&fd,&optlen);
	return fd;
}
int checksockfd(int fd,int epfd,int *errn){
	int r0;
	struct epoll_event ev;
	fd_set efds,wfds;
	if(epfd>=0){
#ifdef USE_EPOLL_PWAIT2
		if((r0=epoll_pwait2(epfd,&ev,1,pcts,NULL))<0){
#else
		if((r0=epoll_pwait(epfd,&ev,1,ctout,NULL))<0){
#endif
			*errn=errno;
			return -1;
		}
		else if(r0>0&&ev.events&EPOLLERR){
			*errn=sockerr(fd);
			return 1;
		}else return 0;
	}
	//checking with epoll completed. now treat the case with select
	FD_ZERO(&wfds);
	FD_ZERO(&efds);
	FD_SET(fd,&wfds);
	FD_SET(fd,&efds);
	if((r0=pselect(fd+1,NULL,&wfds,&efds,pcts,NULL))<0){
		*errn=errno;
		return -1;
	}else if(r0>0&&FD_ISSET(fd,&efds)){
//		puts("efds");
		*errn=sockerr(fd);
		return 1;
	}else return 0;
}

void errexit(const char *msg){
	write(STDERR_FILENO,msg,strlen(msg));
	exit(1);
}
size_t fill_icmphdr(void *s,size_t offset,struct argandret *aar){
	struct icmphdr *h;
	h=(struct icmphdr *)((char *)s+offset);
	h->type=icmp_type;
	h->un.echo.sequence=htons(icmp_seq0);
	h->un.echo.id=htons(icmp_echoid);
	aar->icmp_seqc=icmp_seq0;
	aar->icmp_idc=icmp_echoid;
	return sizeof(*h);
}
void process_icmphdr(void *s,size_t offset,struct argandret *aar){
	struct icmphdr *h;
	h=(struct icmphdr *)((char *)s+offset);
	switch(icmp_seqmode){
		case RAND:
			aar->icmp_seqc=(uint16_t)rand();
			break;
		case FIX:
			break;
		case INC:
			++aar->icmp_seqc;
			break;
		case DEC:
			--aar->icmp_seqc;
			break;
		default:
			break;
	}
	switch(icmp_idmode){
		case RAND:
			aar->icmp_idc=(uint16_t)rand();
			break;
		case FIX:
			break;
		case INC:
			++aar->icmp_idc;
			break;
		case DEC:
			--aar->icmp_idc;
			break;
		default:
			break;
	}
	h->un.echo.sequence=htons(aar->icmp_seqc);
	h->un.echo.id=htons(aar->icmp_idc);
	h->checksum=0;
	h->checksum=cksum(h,sizeof(*h));
}
size_t fill_all(void *s,void *aar){
	size_t ret,i;
	ret=0;
	i=0;
	while(fhdr[i]){
	offsets[i]=ret;
	ret+=fhdr[i](s,ret,(struct argandret *)aar);
	++i;
	}
	if(data_size>0&&data_from_file){
		memcpy((char *)s+ret,data_from_file,data_size);
		ret+=data_size;
	}
	return ret;
}
void proc_all(void *s,void *aar){
	size_t i;
	i=0;
	while(phdr[i]){
	phdr[i](s,offsets[i],(struct argandret *)aar);
	++i;
	}
}

int newerr(int errn){
	long r0;
	pthread_mutex_lock(&gmutex);
	for(r0=0;r0<nhidden_errors;++r0){
		if(hidden_errors[r0]==errn){
			pthread_mutex_unlock(&gmutex);
			return 0;
		}
	}
		if(nhidden_errors>=MAX_HIDDEN_ERRORS)
		{
			nhidden_errors=0;
		}
		hidden_errors[nhidden_errors]=errn;
		++nhidden_errors;

pthread_mutex_unlock(&gmutex);
return errn;
}

int writing(void *arg){
union {
	struct sockaddr a;
	struct sockaddr_in in;
} uaddr;
void *sbuf;
struct timespec ts_old,ts_new,ts_use;
struct epoll_event epevent;
ssize_t r;
char inputp[INPUT_SIZE];
long id;
size_t sent=0,sent_ok=0,sent_size=0,aborted=0,nerror=0;
int fd,lasterr=0,r0,r1,epfd;
memset(&uaddr,0,sizeof(uaddr));
id=((struct argandret *)arg)->id;
switch(base_proto){
	case P_ICMP:
		uaddr.a.sa_family=AF_INET;
		memcpy(&uaddr.in.sin_addr,&ip_addr,sizeof(ip_addr));
		if(sock_type==TYPE_AUTO){
			fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
			if(fd<0){
			fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
			if(fd<0){
			if((r0=newerr(errno))){
			r1=sprintf(inputp,"%ld: SOCK_DGRAM(ICMP):%s (same errors following will be hidden)\n",id,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			}
			goto err1;
			}
		}
		}else if(sock_type==TYPE_RAW){
			fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
			if(fd<0){
				if((r0=newerr(errno))){
				r1=sprintf(inputp,"%ld: SOCK_RAW:%s (same errors following will be hidden)\n",id,strerror(r0));
				write(STDERR_FILENO,inputp,r1);
				}
				goto err1;
			}
		}else if(sock_type==TYPE_DGRAM){
			fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
			if(fd<0){
				if((r0=newerr(errno))){
				r1=sprintf(inputp,"%ld: SOCK_DGRAM(ICMP):%s (same errors following will be hidden)\n",id,strerror(r0));
				write(STDERR_FILENO,inputp,r1);
				}
				goto err1;
			}
		}
		if(bind_device){
			if(setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,bind_device,strlen(bind_device)+1)<0){
		if((r0=newerr(errno))){
		r1=sprintf(inputp,"%ld: cannot bind device:%s (same errors following will be hidden)\n",id,strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		}
		goto err2;
		}
	}		
		break;
	case P_UDP:
		uaddr.a.sa_family=AF_INET;
		uaddr.in.sin_addr.s_addr=inet_addr(target);
		uaddr.in.sin_port=htons(sin_port);
			fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
			if(fd<0){
				if((r0=newerr(errno))){
				r1=sprintf(inputp,"%ld: SOCK_DGRAM:%s (same errors following will be hidden)\n",id,strerror(r0));
				write(STDERR_FILENO,inputp,r1);
				}
				goto err1;
			}
		if(bind_device){
			if(setsockopt(fd,SOL_SOCKET,SO_BINDTODEVICE,bind_device,strlen(bind_device)+1)<0){
		if((r0=newerr(errno))){
		r1=sprintf(inputp,"%ld: cannot bind device:%s (same errors following will be hidden)\n",id,strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		}
		goto err2;
		}
	}		
		break;

	default:
		return 1;
}
fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
if(connect(fd,&uaddr.a,sizeof(uaddr))<0){
	if((r0=newerr(errno))){
	r1=sprintf(inputp,"%ld: connect:%s (same errors following will be hidden)\n",id,strerror(r0));
	write(STDERR_FILENO,inputp,r1);
	}
	goto err2;
}
pthread_mutex_lock(&gmutex);
sbuf=malloc(packlen);
if(sbuf==NULL){
	if((r0=newerr(errno)))goto malloc_err;
	r1=sprintf(inputp,"%ld: cannot malloc:%s (same errors following will be hidden)\n",id,strerror(r0));
	write(STDERR_FILENO,inputp,r1);
	goto malloc_err;
}//malloced
goto malloc_ok;
malloc_err:
pthread_mutex_unlock(&gmutex);
goto err2;
malloc_ok:
ts_old.tv_sec=0;
ts_old.tv_nsec=0;
r=0;
++rthreads;
pthread_mutex_unlock(&gmutex);
memset(sbuf,0,packlen);
fill_all(sbuf,arg);
//fprintf(stderr,"%ld: ready,d=%d\n",id,smutex);
//pthread_mutex_lock(&smutex);
//pthread_mutex_unlock(&smutex);
//fprintf(stderr,"%ld: started\n",id);
//start sending
//ioctl(fd,FIONBIO,"\1");
if(check_mode==CHECK_AUTO||check_mode==CHECK_EPOLL){
	epfd=epoll_create(1);
	if(epfd<0&&check_mode==CHECK_EPOLL){
		if((r0=newerr(errno))){
		r1=sprintf(inputp,"%ld: cannot create epoll:%s (same errors following will be hidden)\n",id,strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		}
		goto err3;
	}
}
else epfd=-1;
if(epfd>=0){
epevent.events=EPOLLOUT|EPOLLERR;
epevent.data.fd=0;
if(epoll_ctl(epfd,EPOLL_CTL_ADD,fd,&epevent)<0){
	if(check_mode==CHECK_EPOLL){
	if((r0=newerr(errno))){
	r1=sprintf(inputp,"%ld: cannot ctl epoll:%s (same errors following will be hidden)\n",id,strerror(r0));
	write(STDERR_FILENO,inputp,r1);
	}
	goto err4;
	}
	close(epfd);
	epfd=-1;
}
}
waitf(&smutex,0);
while(running){
	if(!update_ok||r>=0)proc_all(sbuf,arg);
	if(check_mode!=CHECK_NO){
		if(!(r1=checksockfd(fd,epfd,&r0)))goto noerr;
		if(r1==1)++aborted;
		else if(r0!=EINTR||running)++nerror;
		else goto ignore_err;
		if(lasterr!=r0&&(r0=newerr(r0))){
			r1=sprintf(inputp,"\n%ld: %s before writing %lu th packet:%s (same errors following will be hidden)\n",id,r1>0?"error avoided":"cannot check",sent,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			lasterr=errno;
		}
ignore_err:
			r=-1;
			continue;
	}
noerr:
	r=write(fd,sbuf,packlen);
	++sent;
	if(r<0){
		r0=errno;
		++nerror;
		if(lasterr!=r0&&(r0=newerr(r0))){
			r1=sprintf(inputp,"\n%ld: error at writing %lu th packet:%s (same errors following will be hidden)\n",id,sent,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			lasterr=errno;
		}
	}
	else {
	++sent_ok;
	sent_size+=r;
	//fprintf(stderr,"%hu\n",icmp_seqc);
	}
	if(sleep_between_sents){
		clock_gettime(CLOCK_MONOTONIC,&ts_new);
			ts_use.tv_sec=ts_new.tv_sec-ts_old.tv_sec;
			if(ts_new.tv_nsec<ts_old.tv_nsec){
				ts_use.tv_nsec=1000000000l+ts_new.tv_nsec-ts_old.tv_nsec;
				--ts_use.tv_sec;
			}//carry
			else ts_use.tv_nsec=ts_new.tv_nsec-ts_old.tv_nsec;
		if(ts_use.tv_sec>ts.tv_sec||(ts_use.tv_sec==ts.tv_sec&&ts_use.tv_nsec>ts.tv_nsec))
		{
			clock_gettime(CLOCK_MONOTONIC,&ts_old);
		}else {
		ts_use.tv_sec=ts.tv_sec-ts_use.tv_sec;
		if(ts.tv_nsec<ts_use.tv_nsec){
			ts_use.tv_nsec=1000000000l+ts.tv_nsec-ts_use.tv_nsec;
			--ts_use.tv_sec;
		}else  ts_use.tv_nsec=ts.tv_nsec-ts_use.tv_nsec;
		nanosleep(&ts_use,NULL);
		clock_gettime(CLOCK_REALTIME,&ts_old);
		}
	}
	if(count){
		if(count_written){
		if(sent_ok>=count)break;
		}else {
		if(sent>=count)break;
		}

	}
}

if(epfd>=0){
	epoll_ctl(epfd,EPOLL_CTL_DEL,fd,NULL);
	close(epfd);
}
close(fd);
((struct argandret *)arg)->sent=sent;
((struct argandret *)arg)->sent_ok=sent_ok;
((struct argandret *)arg)->sent_size=sent_size;
((struct argandret *)arg)->aborted=aborted;
((struct argandret *)arg)->nerror=nerror;
pthread_mutex_lock(&gmutex);
free(sbuf);
pthread_mutex_unlock(&gmutex);
return 0;
err4:
if(epfd>=0)close(epfd);
err3:
pthread_mutex_lock(&gmutex);
free(sbuf);
pthread_mutex_unlock(&gmutex);
err2:
close(fd);
err1:
//usleep(1000);
//pthread_mutex_unlock(&gmutex);
return 1;
}

int prewriting(void *arg){
	int r;
	//char buf[32];
	r=writing(arg);
	if(r==0)
	((struct argandret *)arg)->end=1;
	else{
	pthread_mutex_lock(&gmutex);
	//sprintf(buf,"%ld: Failed\n",((struct argandret *)arg)->id);
	//write(STDERR_FILENO,buf,strlen(buf));
	((struct argandret *)arg)->end=2;
	++rthreads;
	pthread_mutex_unlock(&gmutex);
	}
	((struct argandret *)arg)->mutex=1;
	wakef(&((struct argandret *)arg)->mutex,1);
	return r;
}
void end_all_sleeping(void){
	long r1;
	pthread_mutex_lock(&gmutex);
	for(r1=0;r1<nthreads;++r1){
		if(targ[r1].id!=-1&&targ[r1].end==0)
			tgkill(pid,targ[r1].tid,SIGUSR1);
	}
	pthread_mutex_unlock(&gmutex);
}
uint32_t read_stdin_mutex;
int read_stdin(void *arg){
	ssize_t r;
	long r1,r2,r3,r0;
	char *p;
	char *saveptr;
	fd_set fds;
	*lastcmd=0;
	for(;;){
		FD_ZERO(&fds);
		FD_SET(STDIN_FILENO,&fds);
		if(select(STDIN_FILENO+1,&fds,NULL,NULL,NULL)<0){
			
	//fprintf(stderr,"\n%d/%d:selecterr\n",getpid(),gettid());
			break;
		}
		if(!FD_ISSET(STDIN_FILENO,&fds))break;
	//fprintf(stderr,"\n%d/%d:select\n",getpid(),gettid());
		r=read(STDIN_FILENO,input,INPUT_SIZE);
		if(r==0){
end:
			running=0;
			end_all_sleeping();
			break;
		}
		else if(r<0)break;
		p=memchr(input,'\n',r);
		if(p)*p=0;
		else continue;
redo_cmd:
		if(p==input){
			strcpy(input,lastcmd);
		}else strcpy(lastcmd,input);
		strtok_r(input," ",&saveptr);
		if(strcmp(input,"end")==0||strcmp(input,"quit")==0||strcmp(input,"q")==0||strcmp(input,"exit")==0){
			goto end;
		}else if(strcmp(input,"err")==0||strcmp(input,"error")==0||strcmp(input,"e")==0){
			pthread_mutex_lock(&gmutex);
			nhidden_errors=0;
			pthread_mutex_unlock(&gmutex);
			continue;
		}else if(strcmp(input,"t")==0||strcmp(input,"thread")==0||strcmp(input,"threads")==0){
//		pthread_mutex_lock(&gmutex);
		r0=r2=r3=0;
		for(r1=0;r1<nthreads;++r1){
			if(targ[r1].id==-1){
				++r2;
				continue;
			}
			if(targ[r1].end==1)++r3;
			else if(targ[r1].end==2)++r2;
			else if(targ[r1].end==0)++r0;
		}
		//	pthread_mutex_unlock(&gmutex);
			sprintf(input2,"read_stdin: %ld thread%s active. %ld done. %ld failed.\n",r0,r0==1?" is":"s are",r3,r2);
			write(STDERR_FILENO,input2,strlen(input2));
			continue;
		}else if(strcmp(input,"y")==0||strcmp(input,"redo")==0){
			p=input;
			goto redo_cmd;
		}else if(strcmp(input,"kill")==0||strcmp(input,"k")==0){
			p=strtok_r(NULL," ",&saveptr);
			if(p){
			r1=sscanf(p,"%ld",&r2);
			if(r1<1)goto inarg;
			}
			else r2=SIGKILL;
			kill(pid,r2);
			continue;
		}else if(strcmp(input,"alarm")==0||strcmp(input,"alrm")==0){
			p=strtok_r(NULL," ",&saveptr);
			if(p){
			r1=sscanf(p,"%ld",&r2);
			if(r1<1)goto inarg;
			}
			else r2=0;
			alarm(r2);
			continue;
		}else if(strcmp(input,"echo2")==0){
			p=strtok_r(NULL," ",&saveptr);
			if(p){
				strcpy(input,lastcmd);
				p[r=strlen(p)]='\n';
				p[r+1]=0;
				write(STDERR_FILENO,p,strlen(p));
			}
			else goto noarg;
			continue;
		}else if(strcmp(input,"echo")==0||strcmp(input,"echo1")==0){
				p=strtok_r(NULL," ",&saveptr);
			if(p){
				strcpy(input,lastcmd);
				p[r=strlen(p)]='\n';
				p[r+1]=0;
				write(STDOUT_FILENO,p,strlen(p));
			}
			else goto noarg;
			continue;
		}else {
			sprintf(input2,"read_stdin: invaild command:\"%s\"\n",input);
			write(STDERR_FILENO,input2,strlen(input2));
			continue;
noarg:
			sprintf(input2,"read_stdin: no (enough) argument with \"%s\"\n",input);
			write(STDERR_FILENO,input2,strlen(input2));
			continue;
inarg:
			sprintf(input2,"read_stdin: invaild argument with \"%s\"\n",input);
			write(STDERR_FILENO,input2,strlen(input2));
			continue;


		}
	}
	read_stdin_mutex=1;
	wakef(&read_stdin_mutex,1);
	//fprintf(stderr,"\n%d/%d:end\n",getpid(),gettid());
	//select(0,NULL,NULL,NULL,NULL);
	return 0;
}

void psig(int sig){
	switch(sig){
		case SIGINT:
			running=0;
			//fprintf(stderr,"\nSIGINT\n");
			//++intcount;
			//printf("%ld\n",intcount);
			//if(intcount>1)signal(SIGINT,SIG_DFL);
			end_all_sleeping();
			break;
		case SIGABRT:
			//fprintf(stderr,"\nSIGABRT\n");
			running=0;
			break;
		case SIGALRM:
			//fprintf(stderr,"\nSIGALRM\n");
			running=0;
			break;
		case SIGUSR1:
			//running=0;
			//fprintf(stderr,"\n%d/%d:SIGUSR1\n",getpid(),gettid());
			break;
		default:
			break;
	}
}
int main(int argc,char **argv){
	signed long int i,r0,r1,r2;
	off_t foff;
	enum __proto proto;
	ssize_t r;
	int fd;
#ifdef RELEASE
	if(strcmp(bfname(argv[0]),"synkill")==0)
#else
	if(strcmp(bfname(argv[0]),"synkill_g")==0||strcmp(bfname(argv[0]),"synkill")==0)
#endif
	{
		errexit("will be supported in the future\n");
	}
	if(argc<2){
		write(STDOUT_FILENO,"--help\n",7);
		return 0;
	}
	for(i=1;i<argc;++i){
		if(strcmp(argv[i],"--help")==0){
			write(STDOUT_FILENO,"usage\n",6);
			return 0;
		}else if(strcmp(argv[i],"--license")==0){
			write(STDOUT_FILENO,license,strlen(license));
			return 0;
		}else if(strcmp(argv[i],"--icmp")==0){
			upper_proto=P_ICMP;
		}else if(strcmp(argv[i],"--icmp-seq-rand")==0){
			icmp_seqmode=RAND;
		}else if(strcmp(argv[i],"--icmp-seq-fix")==0){
			icmp_seqmode=FIX;
		}else if(strcmp(argv[i],"--icmp-seq-inc")==0){
			icmp_seqmode=INC;
		}else if(strcmp(argv[i],"--icmp-seq-dec")==0){
			icmp_seqmode=DEC;
		}else if(strcmp(argv[i],"--icmp-seq")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&icmp_seq0);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--icmp-id-inc")==0){
			icmp_idmode=INC;
		}else if(strcmp(argv[i],"--icmp-id-dec")==0){
			icmp_idmode=DEC;
		}else if(strcmp(argv[i],"--icmp-id-fix")==0){
			icmp_idmode=FIX;
		}else if(strcmp(argv[i],"--icmp-id-rand")==0){
			icmp_idmode=RAND;
		}else if(strcmp(argv[i],"--icmp-id")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&icmp_echoid);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--icmp-sock-raw")==0){
			sock_type=TYPE_RAW;
		}else if(strcmp(argv[i],"--icmp-sock-dgram")==0){
			sock_type=TYPE_DGRAM;
		}else if(strcmp(argv[i],"--icmp-sock-auto")==0){
			sock_type=TYPE_AUTO;
		}else if(strcmp(argv[i],"--icmp-echo")==0){
			icmp_type=ICMP_ECHO;
		}else if(strcmp(argv[i],"--icmp-reply")==0){
			icmp_type=ICMP_ECHOREPLY;
		}else if(strcmp(argv[i],"--udp")==0){
			upper_proto=P_UDP;
		}else if(strcmp(argv[i],"-p")==0||strcmp(argv[i],"--port")==0||strcmp(argv[i],"--sin-port")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&sin_port);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--update-force")==0){
			update_ok=0;
		}else if(strcmp(argv[i],"--update-ok")==0){
			update_ok=1;
		}else if(strcmp(argv[i],"--check")==0||strcmp(argv[i],"--check-auto")==0){
			check_mode=CHECK_AUTO;
		}else if(strcmp(argv[i],"--check-select")==0){
			check_mode=CHECK_SELECT;
		}else if(strcmp(argv[i],"--check-epoll")==0){
			check_mode=CHECK_EPOLL;
		}else if(strcmp(argv[i],"--check-no")==0){
			check_mode=CHECK_NO;
		}else if(strcmp(argv[i],"-t")==0||strcmp(argv[i],"--target")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			target=argv[++i];
		}else if(strcmp(argv[i],"-i")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			bind_device=argv[++i];
		}else if(strcmp(argv[i],"-cw")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}			
			r0=sscanf(argv[++i],"%lu",&count);
			if(r0<1)goto err_sarg;
			count_written=1;
		}else if(strcmp(argv[i],"-c")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%lu",&count);
			if(r0<1)goto err_sarg;
			count_written=0;
		}else if(strcmp(argv[i],"--timeout")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=dat2spec(argv[++i],&cts);
			if(r0<1)goto err_sarg;
			//ctv.tv_sec=cts_tv_sec;
			//ctv.tv_usec=cts_tv_nsec/1000;
			ctout=cts.tv_sec*1000000+cts.tv_nsec/1000;
			pcts=&cts;
			//pctv=&ctv;
		} else if(strcmp(argv[i],"--thread")==0||strcmp(argv[i],"-T")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%ld",&nthreads);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--alarm")==0||strcmp(argv[i],"--alrm")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%u",&do_alarm);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--size")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%zu",&data_size);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--data")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			data_from_file=argv[++i];
		}else if(strcmp(argv[i],"--sleep")==0){
			if(i==argc-1){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			sleep_between_sents=1;
			r0=dat2spec(argv[++i],&ts);
			if(r0<1)goto err_sarg;
		}else if(argv[i][0]!='-'){
			target=argv[i];
		}else{
err_sarg:
			fprintf(stderr,"invaild argument:%s (after %s)\n",argv[i],argv[i-1]);
			errexit("Failed\n");
		}
	}
	//arg processing completed
	pid=getpid();
	signal(SIGINT,psig);
	//signal(SIGABRT,psig);
	signal(SIGUSR1,psig);
	signal(SIGALRM,psig);
	if(do_alarm)alarm(do_alarm);
	if(check_mode==CHECK_NONE)check_mode=CHECK_NO;
	if(target!=NULL)fprintf(stderr,"target (%s)\n",target);
	else errexit("no target\nFailed\n");
	if(inet_aton(target,&ip_addr)==0){
		errexit("invaild target\nFailed\n");
	}
	i=0;
	if(upper_proto==P_NONE)upper_proto=P_ICMP;
	if(base_proto==P_NONE)base_proto=upper_proto;
	proto=base_proto;
	packlen=0;
	while(proto!=P_NONE){
	switch(proto){
		case P_ICMP:
			fhdr[i]=fill_icmphdr;
			phdr[i]=process_icmphdr;
			packlen+=sizeof(struct icmphdr);
			++i;
			proto=P_NONE;
			break;
		case P_UDP:
			if(base_proto==P_UDP){
				proto=P_NONE;
				break;
			}
			break;
		default:
			errexit("unknown protocol\nFailed\n");
	}
}
	phdr[i]=NULL;
	fhdr[i]=NULL;
	srand(time(NULL));
	running=1;
	tstack=malloc(nthreads*TSTACK_SIZE);
	if(tstack==NULL){
	perror("cannot malloc");
	goto err0;
	}
//malloced
	targ=malloc(nthreads*sizeof(*targ));
	if(targ==NULL){
	perror("cannot malloc");
	goto err1;
	}
//malloced
	if(data_from_file){
		fd=open(data_from_file,O_RDONLY);
		if(fd<0){
			fprintf(stderr,"cannot open \"%s\":%s\n",data_from_file,strerror(errno));
			goto err2;
		}
		if(data_size==0){
			foff=lseek(fd,0,SEEK_END);
			if(foff==ERR_LSEEK){
cannot_reseek:
				perror("cannot seek file");
				close(fd);
				goto err2;
			}
			if(lseek(fd,0,SEEK_SET)==ERR_LSEEK)goto cannot_reseek;
			else data_size=foff;
		}
		if(data_size>0){
		data_from_file=malloc(data_size);
		if(data_from_file==NULL){
			close(fd);
			perror("cannot malloc");
			goto err2;
			}
		//malloced
		memset(data_from_file,0,data_size);
		r=read(fd,data_from_file,data_size);
		if(r<0){
			perror("cannot read file");
			close(fd);
			goto err3;
		}
		}
		close(fd);
	}
	cthreads=0;
	//pthread_mutexattr_init(&sattr);
	//pthread_mutexattr_settype(&sattr,PTHREAD_MUTEX_ADAPTIVE_NP);
	pthread_mutex_init(&gmutex,NULL);
	//pthread_mutex_init(&smutex,NULL);
	//pthread_mutex_lock(&smutex);
	sent_sum=sent_sum_ok=0;
	packlen+=data_size;
	fd=0;
	read_stdin_mutex=0;
	fd=clone(read_stdin,read_stdin_stack+TSTACK_SIZE,CLONE_FILES|CLONE_FS|CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_PTRACE,NULL);
	for(r1=0;r1<nthreads;++r1)
	{	targ[r1].id=r1;
		targ[r1].sent=0;
		targ[r1].sent_ok=0;
		targ[r1].sent_size=0;
		targ[r1].end=0;
		targ[r1].mutex=0;
	//	pthread_mutex_init(&targ[r1].mutex,NULL);
		if((targ[r1].tid=clone(prewriting,tstack+TSTACK_SIZE+r1*TSTACK_SIZE,CLONE_FS|CLONE_VM|CLONE_THREAD|CLONE_SIGHAND|CLONE_PTRACE,targ+r1))<0){
			fprintf(stderr,"cannot cteate thread %ld:%s\n",r1,strerror(errno));
			targ[r1].id=-1;
			continue;
		}
		++cthreads;
	}
	if(cthreads==0){
		fprintf(stderr,"no thread created\n");
		goto err2;
	}
	r2=1;
	while(r2){
	pthread_mutex_lock(&gmutex);
	r2=(rthreads<cthreads);
	pthread_mutex_unlock(&gmutex);
	}
	fprintf(stderr,"%ld threads started\n",cthreads);
	smutex=1;
	wakef(&smutex,cthreads);
//thread create completed.
	//while(1){
	//	r=read(STDIN_FILENO,input,INPUT_SIZE);
	//	if(r==0)running=0;
	//}
	r2=0;
	for(r1=0;r1<nthreads;++r1){
		if(targ[r1].id==-1)continue;
		waitf(&targ[r1].mutex,0);
		sent_sum+=targ[r1].sent;
		sent_sum_ok+=targ[r1].sent_ok;
		sent_sum_size+=targ[r1].sent_size;
		aborted_sum+=targ[r1].aborted;
		nerror_sum+=targ[r1].nerror;
		if(targ[r1].end==1)++r2;
		//printf("t %ld end\n",targ[r1].id);
	}
	if(fd>0){
		tgkill(pid,fd,SIGUSR1);
		waitf(&read_stdin_mutex,0);
	}
	if(r2<cthreads){
	fprintf(stderr,"%ld threads failed\n",cthreads-r2);
	if(r2==0)errexit("Failed.\n");
	}
	fprintf(stderr,"\n%lu packets tried,%lu (%lu%%),(%lu,%s)written\n",sent_sum,sent_sum_ok,sent_sum!=0?100*sent_sum_ok/sent_sum:0l,sent_sum_size,b2hu(sent_sum_size,input1));
	if(nerror_sum>0){
		if(aborted_sum>0)fprintf(stderr,"%ld errors occured (excluded %ld avoided)\n",nerror_sum,aborted_sum);
		else fprintf(stderr,"%ld errors occured\n",nerror_sum);
	}
	free(tstack);
	free(targ);
	if(data_from_file!=NULL)free(data_from_file);
	write(STDERR_FILENO,"Done\n",strlen("Done\n"));
	return 0;
err3:
	if(data_from_file!=NULL)free(data_from_file);
err2:
	if(targ!=NULL)free(targ);
err1:
	if(tstack!=NULL)free(tstack);
err0:
	errexit("Failed\n");
return -1;
}

