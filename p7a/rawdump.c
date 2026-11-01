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
#include <sys/stat.h>

#define TR "/sys/kernel/tracing"
#define PAGE 4096UL

static int wr(const char *p, const char *s)
{
    int fd = open(p, O_WRONLY);
    if (fd < 0)
        return -1;
    int r = (int)write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -1 : 0;
}

static void pin(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

static long read_fd(int fd, unsigned char *buf, size_t cap)
{
    size_t tot = 0;
    while (tot < cap) {
        ssize_t r = read(fd, buf + tot, cap - tot);
        if (r <= 0)
            break;
        tot += (size_t)r;
    }
    return (long)tot;
}

static unsigned u32(const unsigned char *b, size_t o)
{
    unsigned v;
    memcpy(&v, b + o, 4);
    return v;
}

static unsigned long long u64(const unsigned char *b, size_t o)
{
    unsigned long long v;
    memcpy(&v, b + o, 8);
    return v;
}

int main(int argc, char **argv)
{
    int cpu = argc > 1 ? atoi(argv[1]) : 2;
    int me = getpid();
    unsigned char *buf = malloc(48u << 20);
    unsigned char *m;
    size_t len = 4u << 20;

    if (!buf)
        return 1;
    pin(cpu);
    wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:kmem_cache_alloc\n");
    wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_free\n");
    wr(TR "/events/kmem/rss_stat/trigger", "enable_event:kmem:mm_page_alloc\n");

    /* force rss_stat so the enable_event actions fire */
    m = mmap(NULL, 32u << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m != MAP_FAILED) {
        for (size_t i = 0; i < (32u << 20); i += PAGE)
            m[i] = 1;
        munmap(m, 32u << 20);
    }
    usleep(50000);

    wr(TR "/tracing_on", "0");
    wr(TR "/trace", "\n");
    for (int c = 0; c < 8; c++) {
        char p[128];
        snprintf(p, sizeof(p), TR "/per_cpu/cpu%d/trace_pipe_raw", c);
        int fd = open(p, O_RDONLY | O_NONBLOCK);
        if (fd >= 0) {
            while (read(fd, buf, 65536) > 0)
                ;
            close(fd);
        }
    }
    wr(TR "/tracing_on", "1");

    m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    for (size_t i = 0; i < len; i += PAGE)
        m[i] = 1;
    munmap(m, len);
    usleep(30000);
    wr(TR "/tracing_on", "0");

    for (int c = 0; c < 8; c++) {
        char p[128], out[128];
        snprintf(p, sizeof(p), TR "/per_cpu/cpu%d/trace_pipe_raw", c);
        int fd = open(p, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;
        long n = read_fd(fd, buf, 48u << 20);
        close(fd);
        if (n <= 0)
            continue;
        snprintf(out, sizeof(out), "/data/local/tmp/raw_cpu%d.bin", c);
        int of = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (of >= 0) {
            (void)!write(of, buf, (size_t)n);
            close(of);
        }
        printf("cpu%d bytes=%ld\n", c, n);
        if (c != cpu)
            continue;
        int shown = 0;
        for (size_t i = 16; i + 40 <= (size_t)n && shown < 40; i += 4) {
            if ((int)u32(buf, i - 4) != me)
                continue;
            printf("off=%#zx type=%#x flags=%#x pid=%d | %016llx %016llx "
                   "%016llx %016llx %016llx\n",
                   i, u32(buf, i - 8), u32(buf, i - 6) & 0xff,
                   (int)u32(buf, i - 4), u64(buf, i), u64(buf, i + 8),
                   u64(buf, i + 16), u64(buf, i + 24), u64(buf, i + 32));
            printf("  hex:");
            for (int k = -16; k < 48; k++)
                printf(" %02x", buf[i + k]);
            printf("\n");
            shown++;
        }
        printf("shown=%d\n", shown);
    }
    return 0;
}
