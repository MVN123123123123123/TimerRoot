#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>

#define TR "/sys/kernel/tracing"
#define PAGE 4096UL

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0) return -1;
    int r = (int)write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}
static void pin(int cpu) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s); sched_setaffinity(0, sizeof(s), &s); }
static unsigned u32(const unsigned char *b, size_t o) { unsigned v; memcpy(&v,b+o,4); return v; }
static unsigned long long u64(const unsigned char *b, size_t o) { unsigned long long v; memcpy(&v,b+o,8); return v; }

int main(int argc, char **argv)
{
    int cpu = 2, me = getpid();
    size_t sz = argc > 1 ? strtoul(argv[1], 0, 0) : 8192;
    int nw = argc > 2 ? atoi(argv[2]) : 16;
    unsigned char *buf = malloc(48u << 20);
    int snd = 16 << 20, p[2];
    unsigned char *payload = malloc(sz);

    if (!buf || !payload) return 1;
    memset(payload, 0x41, sz);
    pin(cpu);
    wr(TR "/buffer_size_kb", "8192\n");
    wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:kmem_cache_alloc\n");
    wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_free\n");
    wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_alloc\n");
    {
        char *m = mmap(NULL, 32u << 20, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (m != MAP_FAILED) { for (size_t i=0;i<(32u<<20);i+=PAGE) m[i]=1; munmap(m,32u<<20); }
    }
    usleep(50000);
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, p)) { perror("socketpair"); return 1; }
    setsockopt(p[0], SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));
    setsockopt(p[1], SOL_SOCKET, SO_RCVBUF, &snd, sizeof(snd));

    wr(TR "/tracing_on", "0"); wr(TR "/trace", "\n");
    for (int c=0;c<8;c++) {
        char path[128]; snprintf(path,sizeof(path),TR "/per_cpu/cpu%d/trace_pipe_raw",c);
        int fd=open(path,O_RDONLY|O_NONBLOCK); if(fd>=0){while(read(fd,buf,65536)>0);close(fd);}
    }
    wr(TR "/tracing_on", "1");
    for (int i=0;i<nw;i++) {
        ssize_t r = write(p[0], payload, sz);
        if (r != (ssize_t)sz) printf("write %d -> %zd errno=%d\n", i, r, errno);
    }
    usleep(20000);
    wr(TR "/tracing_on", "0");

    char path[128]; snprintf(path,sizeof(path),TR "/per_cpu/cpu%d/trace_pipe_raw",cpu);
    int fd=open(path,O_RDONLY|O_NONBLOCK);
    size_t tot=0; while(tot<(48u<<20)){ssize_t r=read(fd,buf+tot,(48u<<20)-tot); if(r<=0)break; tot+=r;}
    close(fd);
    printf("size=%zu writes=%d bytes=%zu\n", sz, nw, tot);

    int hist[12]={0}, kmhist[16]={0};
    for (size_t i=16;i+40<=tot;i+=4) {
        if ((int)u32(buf,i-4)!=me) continue;
        unsigned type=u32(buf,i-8)&0xffff;
        if (type==263 || type==262 || type==261) {
            unsigned order=u32(buf,i+8);
            if (order<12) hist[order]++;
        }
        if (type==257) {
            unsigned long long req=u64(buf,i+16);
            int slot = req==0?0:(req<=64?1:req<=128?2:req<=192?3:req==256?4:req==512?5:req==1024?6:req==2048?7:req==4096?8:req==8192?9:req==16384?10:11);
            kmhist[slot]++;
        }
    }
    printf("page orders:");
    for (int i=0;i<12;i++) if (hist[i]) printf(" o%d=%d", i, hist[i]);
    printf("\nkmalloc req: <=64=%d 128=%d 192=%d 256=%d 512=%d 1k=%d 2k=%d 4k=%d 8k=%d 16k=%d other=%d\n",
        kmhist[1],kmhist[2],kmhist[3],kmhist[4],kmhist[5],kmhist[6],kmhist[7],kmhist[8],kmhist[9],kmhist[10],kmhist[11]);
    printf("first page allocs:\n");
    int shown=0;
    for (size_t i=16;i+40<=tot && shown<20;i+=4) {
        if ((int)u32(buf,i-4)!=me) continue;
        unsigned type=u32(buf,i-8)&0xffff;
        if (type==263) {
            printf("  pfn=%#llx order=%u\n", u64(buf,i), u32(buf,i+8));
            shown++;
        }
    }
    return 0;
}
