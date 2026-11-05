/*
 * haku.c —— 局域网设备扫描（Termux / 无 root 也能用）
 *
 * Android 上 SELinux 挡住的不只是 Python：
 *   /proc/net/arp、/proc/net/dev 读不到，netlink 绑定被拒（ip addr/neigh 都失败），
 *   AF_PACKET raw socket 也建不了 —— 所以拿不到 MAC，ARP 扫描这条路整体没有。
 * 能用的：ping 二进制（带 cap_net_raw）、TCP connect、反向 DNS、mDNS/SSDP 组播。
 *
 * 因此本程序 = ICMP 存活（popen ping）+ 非阻塞 connect/poll 批量扫端口
 *             + 反向 DNS + mDNS/SSDP + HTTP(S) 指纹。
 *
 * 用法：
 *   haku                       自动识别本机网段
 *   haku -t 192.168.2.0/24
 *   haku -t 192.168.2.1-60 -p 1-1024
 *   haku --json /sdcard/Download/lan.json
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef HAKU_NO_TLS
#include <openssl/ssl.h>
#endif

#define MAXPORTS 1024
#define MAXLABELS 4
#define MAXTHREADS 256

#define PING_WAIT 1

static const int DEFAULT_PORTS[] = {
    21, 22, 23, 53, 80, 81, 139, 443, 445, 554, 631, 1883, 3306, 3389,
    5000, 5060, 5555, 5900, 8000, 8001, 8008, 8009, 8080, 8123, 8443, 8554,
    8888, 9100, 32400, 34567, 37777, 62078,
};
#define NDEFAULT ((int)(sizeof DEFAULT_PORTS / sizeof DEFAULT_PORTS[0]))

/* ping 不通时用来判“还活着”的端口，一把 poll 并行，最坏 1 个超时 */
static const int LIVE_PORTS[] = {80, 443, 22, 53, 445, 5000, 62078, 8080, 9100};
#define NLIVE ((int)(sizeof LIVE_PORTS / sizeof LIVE_PORTS[0]))

static const struct {
    int port;
    int tls;
} HTTP_PORTS[] = {
    {80, 0}, {81, 0}, {5000, 0}, {8000, 0}, {8080, 0},
    {8123, 0}, {8888, 0}, {443, 1}, {8443, 1},
};
#define NHTTP ((int)(sizeof HTTP_PORTS / sizeof HTTP_PORTS[0]))

static const char *SERVICES[] = {
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local",
    "_workstation._tcp.local", "_ssh._tcp.local", "_smb._tcp.local",
    "_airplay._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local", "_device-info._tcp.local",
    "_companion-link._tcp.local", "_androidtvremote2._tcp.local", "_hap._tcp.local",
};
#define NSERVICES ((int)(sizeof SERVICES / sizeof SERVICES[0]))

/* ---------------------------------------------------------------- 小工具 */

static double now_sec(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static int ms_since(const struct timespec *t0)
{
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (int)((t1.tv_sec - t0->tv_sec) * 1000 +
                 (t1.tv_nsec - t0->tv_nsec) / 1000000);
}

static void u32_to_ip(uint32_t ip, char *out)
{
    snprintf(out, 16, "%u.%u.%u.%u", (ip >> 24) & 255u, (ip >> 16) & 255u,
             (ip >> 8) & 255u, ip & 255u);
}

static int ip_to_u32(const char *s, uint32_t *out)
{
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1)
        return 0;
    *out = ntohl(a.s_addr);
    return 1;
}

/* 定长拷贝：截断而不越界，也避免 GCC 的 -Wformat-truncation 误报 */
static void copy_str(char *dst, size_t n, const char *src)
{
    if (n == 0)
        return;
    size_t l = strlen(src);
    if (l >= n)
        l = n - 1;
    memcpy(dst, src, l);
    dst[l] = 0;
}

/* UTF-8 显示宽度：CJK 算 2 列，否则表格对不齐 */
/* ---------------------------------------------------------------- 网段 */

static int local_prefix(char *ipout, char *maskout)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct ifconf ifc;
    char buf[4096];
    ifc.ifc_len = (int)sizeof buf;
    ifc.ifc_buf = buf;
    if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
        close(fd);
        return -1;
    }
    int best = -1;
    int best_rank = 9;
    size_t pos = 0;
    while (pos + sizeof(struct ifreq) <= (size_t)ifc.ifc_len) {
        struct ifreq *ir = (struct ifreq *)(buf + pos);
        pos += sizeof(struct ifreq);
        if (ir->ifr_addr.sa_family != AF_INET)
            continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)&ir->ifr_addr;
        uint32_t a = ntohl(sin->sin_addr.s_addr);
        if (a >> 24 == 127 || a == 0)
            continue;
        struct ifreq m;
        memset(&m, 0, sizeof m);
        memcpy(m.ifr_name, ir->ifr_name, IFNAMSIZ);
        uint32_t mask = 0xFFFFFF00u;
        if (ioctl(fd, SIOCGIFNETMASK, &m) == 0) {
            struct sockaddr_in *ms = (struct sockaddr_in *)&m.ifr_addr;
            mask = ntohl(ms->sin_addr.s_addr);
        }
        if (mask == 0)
            mask = 0xFFFFFF00u;
        /* 手机常同时有移动数据(100.64/10 之类)与 Wi-Fi，优先取常见的家用网段 */
        int rank = 3;
        if ((a & 0xFFFF0000u) == 0xC0A80000u)      /* 192.168/16 */
            rank = 0;
        else if ((a & 0xFF000000u) == 0x0A000000u) /* 10/8 */
            rank = 1;
        else if ((a & 0xFFF00000u) == 0xAC100000u) /* 172.16/12 */
            rank = 2;
        if (best < 0 || rank < best_rank) {
            best = 0;
            best_rank = rank;
            u32_to_ip(a, ipout);
            u32_to_ip(mask, maskout);
        }
    }
    close(fd);
    return best < 0 ? -1 : 1;
}

static int fallback_local(char *ipout)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    /* 不真正发包，只让内核选路 */
    if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in me;
    socklen_t len = sizeof me;
    if (getsockname(fd, (struct sockaddr *)&me, &len) < 0) {
        close(fd);
        return -1;
    }
    u32_to_ip(ntohl(me.sin_addr.s_addr), ipout);
    close(fd);
    return 0;
}

static int prefix_bits(uint32_t mask)
{
    int n = 0;
    for (int i = 31; i >= 0; i--) {
        if (mask & (1u << i))
            n++;
        else
            break;
    }
    return n;
}

static int parse_targets(const char *spec, uint32_t **out)
{
    int cap = 64, n = 0;
    uint32_t *v = malloc((size_t)cap * sizeof *v);
    if (!v)
        return 0;

    char *copy = strdup(spec);
    if (!copy) {
        free(v);
        return 0;
    }
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ')
            tok++;
        char *slash = strchr(tok, '/');
        char *dash = strchr(tok, '-');
        if (slash) {
            *slash = 0;
            uint32_t base;
            if (!ip_to_u32(tok, &base))
                continue;
            int bits = atoi(slash + 1);
            if (bits < 8)
                bits = 8;
            if (bits > 30)
                bits = 30;
            uint32_t size = 1u << (32 - bits);
            for (uint32_t i = 1; i + 1 < size; i++) {
                if (n == cap) {
                    cap *= 2;
                    uint32_t *nv = realloc(v, (size_t)cap * sizeof *v);
                    if (!nv) {
                        free(v);
                        free(copy);
                        return n;
                    }
                    v = nv;
                }
                v[n++] = base + i;
                if (n > 4096)
                    break;
            }
        } else if (dash) {
            *dash = 0;
            uint32_t head;
            if (!ip_to_u32(tok, &head))
                continue;
            int a = (int)(head & 255u), b = atoi(dash + 1);
            uint32_t base = head & 0xFFFFFF00u;
            for (int i = a; i <= b; i++) {
                if (n == cap) {
                    cap *= 2;
                    uint32_t *nv = realloc(v, (size_t)cap * sizeof *v);
                    if (!nv) {
                        free(v);
                        free(copy);
                        return n;
                    }
                    v = nv;
                }
                v[n++] = base | (uint32_t)i;
            }
        } else {
            uint32_t ip;
            if (!ip_to_u32(tok, &ip))
                continue;
            if (n == cap) {
                cap *= 2;
                uint32_t *nv = realloc(v, (size_t)cap * sizeof *v);
                if (!nv) {
                    free(v);
                    free(copy);
                    return n;
                }
                v = nv;
            }
            v[n++] = ip;
        }
    }
    free(copy);
    *out = v;
    return n;
}

static int parse_ports(const char *spec, int *out, int max)
{
    int n = 0;
    char *copy = strdup(spec);
    if (!copy)
        return 0;
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        char *dash = strchr(tok, '-');
        if (dash) {
            *dash = 0;
            int a = atoi(tok), b = atoi(dash + 1);
            for (int p = a; p <= b && n < max; p++)
                if (p > 0 && p < 65536)
                    out[n++] = p;
        } else {
            int p = atoi(tok);
            if (p > 0 && p < 65536 && n < max)
                out[n++] = p;
        }
    }
    free(copy);
    return n;
}

/* ---------------------------------------------------------------- 探测原语 */

static int ping_once(uint32_t ip, double *rtt, int *ttl)
{
    char ipbuf[16], cmd[128];
    u32_to_ip(ip, ipbuf);
    /* ip 只可能来自我们解析出的点分十进制，不会带 shell 元字符 */
    snprintf(cmd, sizeof cmd, "ping -n -c 1 -W %d %s 2>/dev/null", PING_WAIT, ipbuf);
    FILE *pp = popen(cmd, "r");
    if (!pp)
        return 0;
    char line[512];
    int got = 0;
    *rtt = 0;
    *ttl = 0;
    while (fgets(line, sizeof line, pp)) {
        char *t = strstr(line, "time=");
        if (t) {
            char *p = t + 5;
            while (*p && !isdigit((unsigned char)*p) && *p != '.')
                p++;
            if (*p) {
                *rtt = strtod(p, NULL);
                got = 1;
            }
        }
        char *l = strstr(line, "ttl=");
        if (l)
            *ttl = atoi(l + 4);
    }
    int rc = pclose(pp);
    return got && rc == 0;
}

static int scan_ports(uint32_t ip, const int *ports, int nports, int timeout_ms,
                      int *out, int maxout)
{
    int found = 0;
    const int CH = 192;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);

    for (int base = 0; base < nports; base += CH) {
        int cnt = nports - base;
        if (cnt > CH)
            cnt = CH;

        struct pollfd fds[192];
        int pidx[192];
        int nfd = 0;

        for (int i = 0; i < cnt; i++) {
            int port = ports[base + i];
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0)
                continue;
            int fl = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, fl | O_NONBLOCK);
            sa.sin_port = htons((uint16_t)port);
            int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
            if (rc == 0) {
                if (found < maxout)
                    out[found++] = port;
                close(fd);
                continue;
            }
            if (errno != EINPROGRESS) {
                close(fd);
                continue;
            }
            fds[nfd].fd = fd;
            fds[nfd].events = POLLOUT;
            fds[nfd].revents = 0;
            pidx[nfd] = port;
            nfd++;
        }

        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int remaining = nfd;
        while (remaining > 0) {
            int left = timeout_ms - ms_since(&t0);
            if (left < 0)
                left = 0;
            int pr = poll(fds, (nfds_t)nfd, left);
            if (pr <= 0)
                break;
            for (int i = 0; i < nfd; i++) {
                if (fds[i].fd < 0 || fds[i].revents == 0)
                    continue;
                int err = 0;
                socklen_t el = sizeof err;
                if (getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
                    if (found < maxout)
                        out[found++] = pidx[i];
                }
                close(fds[i].fd);
                fds[i].fd = -1;
                remaining--;
            }
        }
        for (int i = 0; i < nfd; i++)
            if (fds[i].fd >= 0)
                close(fds[i].fd);
    }

    for (int i = 1; i < found; i++) { /* 端口数很少，插入排序够 */
        int x = out[i], j = i - 1;
        while (j >= 0 && out[j] > x) {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = x;
    }
    return found;
}

static void rdns(uint32_t ip, char *out, size_t n)
{
    out[0] = 0;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip);
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof sa, host, sizeof host, NULL, 0,
                    NI_NAMEREQD) == 0)
        copy_str(out, n, host);
}

/* ---------------------------------------------------------------- MAC / 厂商 */

/*
 * Linux 上 /proc/net/arp 普通用户可读，ping 过之后每个同网段主机的条目就在里面。
 * Android 上这个文件被 SELinux 挡住，读不到就静默跳过（不显示 MAC 列）。
 * HAKU_ARP_FILE 是给测试用的覆盖入口。
 */
static int arp_lookup(uint32_t ip, char *out, size_t outsz)
{
    const char *path = getenv("HAKU_ARP_FILE");
    if (!path || !*path)
        path = "/proc/net/arp";
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char want[16];
    u32_to_ip(ip, want);
    char line[256];
    int found = -1;
    while (fgets(line, sizeof line, f)) {
        char a[32], flags[16], hw[32];
        if (sscanf(line, "%31s %*s %15s %31s", a, flags, hw) != 3)
            continue;
        if (strcmp(a, want) != 0 || strcmp(flags, "0x2") != 0)
            continue;
        if (strcmp(hw, "00:00:00:00:00:00") == 0)
            continue;
        copy_str(out, outsz, hw);
        found = 0;
        break;
    }
    fclose(f);
    return found;
}

typedef struct {
    uint32_t key;
    char vendor[44];
} oui_t;

static oui_t *g_oui;
static int g_noui;

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* 接受 00-00-0C / 00000C / 00:00:0C，取前 6 个十六进制位 */
static int parse_prefix(const char *s, uint32_t *out)
{
    int nib[6], n = 0;
    for (const char *p = s; *p && n < 6; p++) {
        int v = hexval((unsigned char)*p);
        if (v >= 0)
            nib[n++] = v;
        else if (*p != '-' && *p != ':' && *p != ' ')
            return 0;
    }
    if (n < 6)
        return 0;
    uint32_t key = 0;
    for (int i = 0; i < 6; i++)
        key = (key << 4) | (uint32_t)nib[i];
    *out = key;
    return 1;
}

static int cmp_oui(const void *a, const void *b)
{
    const oui_t *x = a, *y = b;
    return x->key < y->key ? -1 : (x->key > y->key ? 1 : 0);
}

/*
 * OUI 库：优先 ieee-data 的 oui.txt，其次 nmap-mac-prefixes，再次 oui.csv。
 * 都没有就只显示 MAC，不显示厂商。HAKU_OUI_FILE 可覆盖。
 */
static int oui_load(void)
{
    if (g_oui)
        return g_noui;
    static const char *cands[] = {
        "/usr/share/ieee-data/oui.txt",
        "/data/data/com.termux/files/usr/share/ieee-data/oui.txt",
        "/usr/share/nmap/nmap-mac-prefixes",
        "/usr/share/ieee-data/oui.csv",
    };
    FILE *f = NULL;
    const char *env = getenv("HAKU_OUI_FILE");
    if (env && *env)
        f = fopen(env, "r");
    /* Termux 的 $PREFIX 不在 /usr，单独拼一条 */
    const char *pfx = getenv("PREFIX");
    char pfile[512];
    if (!f && pfx && *pfx) {
        snprintf(pfile, sizeof pfile, "%s/share/ieee-data/oui.txt", pfx);
        f = fopen(pfile, "r");
    }
    for (int i = 0; !f && i < (int)(sizeof cands / sizeof cands[0]); i++)
        f = fopen(cands[i], "r");
    if (!f)
        return 0;

    int cap = 65536;
    g_oui = calloc((size_t)cap, sizeof *g_oui);
    if (!g_oui) {
        fclose(f);
        return 0;
    }
    char line[512];
    while (fgets(line, sizeof line, f) && g_noui < cap) {
        if (strstr(line, "(base 16)")) /* oui.txt 里同一前缀的重复段 */
            continue;
        uint32_t key;
        if (!parse_prefix(line, &key))
            continue;
        const char *v = NULL;
        const char *tag = strstr(line, "(hex)");
        if (tag)
            v = tag + 5;
        else if ((tag = strstr(line, "(base 16)")))
            v = tag + 9;
        else { /* nmap-mac-prefixes: "00000C Cisco Systems, Inc" */
            const char *p = line;
            while (*p && *p != ' ' && *p != '\t')
                p++;
            v = p;
        }
        while (*v == ' ' || *v == '\t')
            v++;
        size_t l = strcspn(v, "\r\n");
        if (l == 0)
            continue;
        if (l >= sizeof g_oui[0].vendor)
            l = sizeof g_oui[0].vendor - 1;
        g_oui[g_noui].key = key;
        memcpy(g_oui[g_noui].vendor, v, l);
        g_oui[g_noui].vendor[l] = 0;
        g_noui++;
    }
    fclose(f);
    qsort(g_oui, (size_t)g_noui, sizeof *g_oui, cmp_oui);
    return g_noui;
}

static const char *oui_lookup(const char *mac)
{
    if (oui_load() == 0)
        return "";
    uint32_t key;
    if (!parse_prefix(mac, &key))
        return "";
    oui_t k;
    memset(&k, 0, sizeof k);
    k.key = key;
    oui_t *hit = bsearch(&k, g_oui, (size_t)g_noui, sizeof *g_oui, cmp_oui);
    return hit ? hit->vendor : "";
}

/* ---------------------------------------------------------------- HTTP 指纹 */

static int http_banner(uint32_t ip, int port, int tls, char *out, size_t outsz)
{
    out[0] = 0;
    char ipbuf[16];
    u32_to_ip(ip, ipbuf);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(ip);

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (rc < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
        struct pollfd p = {fd, POLLOUT, 0};
        if (poll(&p, 1, 2500) <= 0) {
            close(fd);
            return -1;
        }
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);

    struct timeval tv = {2, 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

#ifndef HAKU_NO_TLS
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (tls) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            close(fd);
            return -1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        ssl = SSL_new(ctx);
        if (!ssl) {
            SSL_CTX_free(ctx);
            close(fd);
            return -1;
        }
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, ipbuf);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(fd);
            return -1;
        }
    }
#else
    if (tls) { /* 没编 TLS 支持，https 指纹直接放弃 */
        close(fd);
        return -1;
    }
#endif

    char req[256];
    int rn = snprintf(req, sizeof req,
                      "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: haku/1.0\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n",
                      ipbuf);
#ifdef HAKU_NO_TLS
    ssize_t sent = send(fd, req, (size_t)rn, 0);
#else
    ssize_t sent = ssl ? SSL_write(ssl, req, rn) : send(fd, req, (size_t)rn, 0);
#endif
    if (sent <= 0) {
#ifndef HAKU_NO_TLS
        if (ssl) {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
#endif
        close(fd);
        return -1;
    }

    char buf[8192];
    int total = 0;
    while (total < (int)sizeof buf - 1) {
#ifdef HAKU_NO_TLS
        int n = (int)recv(fd, buf + total, sizeof buf - 1 - (size_t)total, 0);
#else
        int n = ssl ? SSL_read(ssl, buf + total, (int)sizeof buf - 1 - total)
                    : (int)recv(fd, buf + total, sizeof buf - 1 - (size_t)total, 0);
#endif
        if (n <= 0)
            break;
        total += n;
    }
    buf[total] = 0;
#ifndef HAKU_NO_TLS
    if (ssl) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }
#endif
    close(fd);

    if (total < 5 || strncmp(buf, "HTTP/", 5) != 0)
        return -1;

    char server[96] = "";
    char *hend = strstr(buf, "\r\n\r\n");
    char *scan = buf;
    while (scan && (!hend || scan < hend)) {
        char *eol = strstr(scan, "\r\n");
        if (!eol)
            break;
        if (strncasecmp(scan, "server:", 7) == 0) {
            char *v = scan + 7;
            while (*v == ' ')
                v++;
            size_t l = (size_t)(eol - v);
            if (l >= sizeof server)
                l = sizeof server - 1;
            memcpy(server, v, l);
            server[l] = 0;
            break;
        }
        scan = eol + 2;
    }

    char title[64] = "";
    if (hend) {
        char *t = strcasestr(hend + 4, "<title");
        if (t) {
            char *gt = strchr(t, '>');
            char *te = gt ? strcasestr(gt + 1, "</title>") : NULL;
            if (gt && te) {
                size_t l = (size_t)(te - (gt + 1));
                if (l >= sizeof title)
                    l = sizeof title - 1;
                size_t k = 0;
                for (size_t i = 0; i < l; i++) {
                    unsigned char c = (unsigned char)gt[1 + i];
                    if (c == '\n' || c == '\r' || c == '\t') {
                        if (k && title[k - 1] != ' ')
                            title[k++] = ' ';
                    } else if (c >= 0x20) {
                        title[k++] = (char)c;
                    }
                }
                title[k] = 0;
            }
        }
    }

    if (server[0] && title[0])
        snprintf(out, outsz, "%s / 「%s」", server, title);
    else if (server[0])
        snprintf(out, outsz, "%s", server);
    else if (title[0])
        snprintf(out, outsz, "「%s」", title);
    else
        snprintf(out, outsz, "HTTP");
    return 0;
}

/* ---------------------------------------------------------------- 标签表 */

typedef struct {
    uint32_t ip;
    char text[96];
} label_t;

typedef struct {
    label_t *v;
    int n, cap;
} labeltab_t;

typedef struct {
    uint32_t ip;
    int alive;
    int has_icmp;
    double rtt;
    int ttl;
    int nports;
    int ports[MAXPORTS];
    char name[128];
    char banner[160];
    int nlabels;
    char labels[MAXLABELS][96];
    int is_cam;
    char cam[240];
    char mac[20];
    char vendor[48];
} host_t;

static void labeltab_add(labeltab_t *t, uint32_t ip, const char *text)
{
    if (!text || !*text)
        return;
    for (int i = 0; i < t->n; i++)
        if (t->v[i].ip == ip && strncasecmp(t->v[i].text, text, 18) == 0)
            return;
    if (t->n == t->cap) {
        int cap = t->cap ? t->cap * 2 : 16;
        label_t *nv = realloc(t->v, (size_t)cap * sizeof *nv);
        if (!nv)
            return;
        t->v = nv;
        t->cap = cap;
    }
    t->v[t->n].ip = ip;
    snprintf(t->v[t->n].text, sizeof t->v[t->n].text, "%s", text);
    t->n++;
}

static void host_label_add(host_t *h, const char *text)
{
    if (!text || !*text)
        return;
    for (int i = 0; i < h->nlabels; i++)
        if (strncasecmp(h->labels[i], text, 18) == 0)
            return;
    if (h->nlabels >= MAXLABELS)
        return;
    snprintf(h->labels[h->nlabels], sizeof h->labels[0], "%s", text);
    h->nlabels++;
}

/* ---------------------------------------------------------------- mDNS */

typedef struct {
    int type;
    char owner[128];
    char value[128];
    int port;
} rr_t;

static int dns_read_name(const uint8_t *buf, int len, int off, char *out, size_t outsz)
{
    size_t used = 0;
    int jumps = 0;
    int next = -1;
    if (outsz == 0)
        return -1;
    out[0] = 0;
    while (off >= 0 && off < len) {
        int b = buf[off];
        if (b == 0) {
            if (next < 0)
                next = off + 1;
            return next;
        }
        if ((b & 0xC0) == 0xC0) {
            if (off + 1 >= len)
                return -1;
            if (next < 0)
                next = off + 2;
            if (++jumps > 16)
                return -1;
            off = ((b & 0x3F) << 8) | buf[off + 1];
            continue;
        }
        int l = b;
        if (l > 63 || off + 1 + l > len)
            return -1;
        if (used + (size_t)l + 2 > outsz)
            return -1;
        if (used)
            out[used++] = '.';
        memcpy(out + used, buf + off + 1, (size_t)l);
        used += (size_t)l;
        out[used] = 0;
        off += 1 + l;
    }
    return -1;
}

static int build_query(uint8_t *buf, size_t cap, const char *name, int qtype)
{
    if (cap < 32)
        return -1;
    memset(buf, 0, 12);
    buf[5] = 1; /* qdcount */
    size_t o = 12;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        if (l <= 0)
            break;
        if (o + 1 + (size_t)l + 6 >= cap)
            return -1;
        buf[o++] = (uint8_t)l;
        memcpy(buf + o, p, (size_t)l);
        o += (size_t)l;
        if (!dot)
            break;
        p = dot + 1;
    }
    if (o + 6 >= cap)
        return -1;
    buf[o++] = 0;
    buf[o++] = (uint8_t)(qtype >> 8);
    buf[o++] = (uint8_t)qtype;
    buf[o++] = 0;
    buf[o++] = 1;
    return (int)o;
}

static void mdns_parse(const uint8_t *buf, int len, rr_t *rrs, int *nrr, int maxrr)
{
    if (len < 12)
        return;
    int qd = (buf[4] << 8) | buf[5];
    int an = (buf[6] << 8) | buf[7];
    int ns = (buf[8] << 8) | buf[9];
    int ar = (buf[10] << 8) | buf[11];
    int off = 12;
    char name[128];

    for (int i = 0; i < qd; i++) {
        off = dns_read_name(buf, len, off, name, sizeof name);
        if (off < 0 || off + 4 > len)
            return;
        off += 4;
    }
    int total = an + ns + ar;
    for (int i = 0; i < total; i++) {
        off = dns_read_name(buf, len, off, name, sizeof name);
        if (off < 0 || off + 10 > len)
            return;
        int type = (buf[off] << 8) | buf[off + 1];
        int rdlen = (buf[off + 8] << 8) | buf[off + 9];
        int rd = off + 10;
        off = rd + rdlen;
        if (off > len)
            return;
        if (*nrr >= maxrr)
            return;
        rr_t *r = &rrs[*nrr];
        memset(r, 0, sizeof *r);
        r->type = type;
        snprintf(r->owner, sizeof r->owner, "%s", name);
        if (type == 1 && rdlen == 4) {
            struct in_addr a;
            memcpy(&a, buf + rd, 4);
            inet_ntop(AF_INET, &a, r->value, sizeof r->value);
            (*nrr)++;
        } else if (type == 12) {
            if (dns_read_name(buf, len, rd, r->value, sizeof r->value) > 0)
                (*nrr)++;
        } else if (type == 33 && rdlen >= 7) {
            r->port = (buf[rd + 4] << 8) | buf[rd + 5];
            if (dns_read_name(buf, len, rd + 6, r->value, sizeof r->value) > 0)
                (*nrr)++;
        }
    }
}

static void split_first(const char *name, char *out, size_t outsz)
{
    const char *dot = strchr(name, '.');
    size_t l = dot ? (size_t)(dot - name) : strlen(name);
    if (l >= outsz)
        l = outsz - 1;
    memcpy(out, name, l);
    out[l] = 0;
}

static void split_srv(const char *owner, char *inst, size_t instsz, char *svc, size_t svcsz)
{
    const char *dot = strchr(owner, '.');
    svc[0] = 0;
    if (!dot) {
        snprintf(inst, instsz, "%s", owner);
        return;
    }
    size_t l = (size_t)(dot - owner);
    if (l >= instsz)
        l = instsz - 1;
    memcpy(inst, owner, l);
    inst[l] = 0;
    const char *s = dot + 1;
    if (*s == '_')
        s++;
    const char *e = strchr(s, '.');
    if (e && e > s) {
        size_t k = (size_t)(e - s);
        if (k >= svcsz)
            k = svcsz - 1;
        memcpy(svc, s, k);
        svc[k] = 0;
    }
}

static void *mdns_thread(void *arg)
{
    labeltab_t *tab = arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&local, sizeof local) < 0) {
        close(fd);
        return NULL;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(5353);
    inet_pton(AF_INET, "224.0.0.251", &dst.sin_addr);

    uint8_t q[256];
    for (int i = 0; i < NSERVICES; i++) {
        int qn = build_query(q, sizeof q, SERVICES[i], 12);
        if (qn > 0)
            sendto(fd, q, (size_t)qn, 0, (struct sockaddr *)&dst, sizeof dst);
    }

    rr_t *rrs = calloc(512, sizeof *rrs);
    if (!rrs) {
        close(fd);
        return NULL;
    }
    int nrr = 0;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint8_t buf[9000];
    while (ms_since(&t0) < 3000) {
        struct pollfd p = {fd, POLLIN, 0};
        int left = 3000 - ms_since(&t0);
        if (left > 300)
            left = 300;
        if (poll(&p, 1, left) <= 0)
            continue;
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0)
            break;
        mdns_parse(buf, (int)n, rrs, &nrr, 512);
    }
    close(fd);

    /* name -> ip，用于把 SRV 实例挂到具体地址上 */
    enum { MAXN = 160 };
    static char nm[MAXN][128], ipv[MAXN][46];
    int nn = 0;
    for (int i = 0; i < nrr && nn < MAXN; i++) {
        if (rrs[i].type == 1) {
            snprintf(nm[nn], sizeof nm[nn], "%s", rrs[i].owner);
            snprintf(ipv[nn], sizeof ipv[nn], "%s", rrs[i].value);
            nn++;
        }
    }
    for (int i = 0; i < nrr; i++) {
        uint32_t ip;
        if (rrs[i].type == 1) {
            char first[128];
            split_first(rrs[i].owner, first, sizeof first);
            if (first[0] && ip_to_u32(rrs[i].value, &ip))
                labeltab_add(tab, ip, first);
        } else if (rrs[i].type == 33) {
            int hit = 0;
            for (int k = 0; k < nn; k++) {
                if (strcasecmp(nm[k], rrs[i].value) == 0) {
                    if (ip_to_u32(ipv[k], &ip))
                        hit = 1;
                    break;
                }
            }
            if (!hit)
                continue;
            char inst[96], svc[32], label[192];
            split_srv(rrs[i].owner, inst, sizeof inst, svc, sizeof svc);
            if (svc[0])
                snprintf(label, sizeof label, "%.95s[%.30s]", inst, svc);
            else
                snprintf(label, sizeof label, "%s", inst);
            labeltab_add(tab, ip, label);
        }
    }
    free(rrs);
    return NULL;
}

/* ---------------------------------------------------------------- SSDP */

static void *ssdp_thread(void *arg)
{
    labeltab_t *tab = arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;
    int ttl = 2;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);

    const char *msg = "M-SEARCH * HTTP/1.1\r\n"
                      "HOST: 239.255.255.250:1900\r\n"
                      "MAN: \"ssdp:discover\"\r\n"
                      "MX: 2\r\n"
                      "ST: ssdp:all\r\n\r\n";
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(1900);
    inet_pton(AF_INET, "239.255.255.250", &dst.sin_addr);
    sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&dst, sizeof dst);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char buf[4096];
    while (ms_since(&t0) < 2500) {
        struct pollfd p = {fd, POLLIN, 0};
        int left = 2500 - ms_since(&t0);
        if (left > 300)
            left = 300;
        if (poll(&p, 1, left) <= 0)
            continue;
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0)
            break;
        buf[n] = 0;
        uint32_t ip = ntohl(from.sin_addr.s_addr);

        const char *keys[] = {"friendlyname:", "modelname:", "modelname:", "server:"};
        const char *label = NULL;
        for (int k = 0; k < 3 && !label; k++) {
            char *p = buf;
            while (p && *p) {
                char *eol = strstr(p, "\r\n");
                if (!eol)
                    break;
                const char *kn = keys[k];
                size_t kl = strlen(kn);
                if (strncasecmp(p, kn, kl) == 0) {
                    char *v = p + kl;
                    while (*v == ' ')
                        v++;
                    size_t l = (size_t)(eol - v);
                    if (l > 0 && l < 95) {
                        static __thread char tmp[96];
                        memcpy(tmp, v, l);
                        tmp[l] = 0;
                        label = tmp;
                        break;
                    }
                }
                p = eol + 2;
            }
        }
        if (label)
            labeltab_add(tab, ip, label);
    }
    close(fd);
    return NULL;
}

/* ---------------------------------------------------------------- 摄像头指纹 */

static int has_port(const host_t *h, int port);      /* 定义在显示区 */
static void put_cell(const char *s, int width);
static void put_fit(const char *s, int width);
static int term_width(void);
static size_t utf8_seq(unsigned char c);
static int cp_width(const unsigned char *p);

/* 按显示列截断（不切断 UTF-8 / 不劈开 CJK） */
static void fit_copy(char *dst, size_t cap, const char *src, int width)
{
    size_t o = 0;
    int used = 0;
    const unsigned char *p = (const unsigned char *)src;
    while (*p && used < width && o + 5 < cap) {
        size_t n = utf8_seq(*p);
        int w = cp_width(p);
        if (used + w > width)
            break;
        memcpy(dst + o, p, n);
        o += n;
        used += w;
        p += n;
    }
    dst[o] = 0;
}

static void cam_append(host_t *h, const char *fmt, ...)
{
    va_list ap;
    size_t used = strlen(h->cam);
    if (used + 4 >= sizeof h->cam)
        return;
    if (used)
        used += (size_t)snprintf(h->cam + used, sizeof h->cam - used, " · ");
    va_start(ap, fmt);
    vsnprintf(h->cam + used, sizeof h->cam - used, fmt, ap);
    va_end(ap);
    h->is_cam = 1;
}

/* 连上 -> 发一段文本请求 -> 收最多 cap-1 字节 */
static int text_request(uint32_t ip, int port, const char *req, char *buf, size_t cap,
                        int timeout_ms)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(ip);

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (rc < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }
        struct pollfd p = {fd, POLLOUT, 0};
        if (poll(&p, 1, timeout_ms) <= 0) {
            close(fd);
            return -1;
        }
        int err = 0;
        socklen_t el = sizeof err;
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);

    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    if (send(fd, req, strlen(req), 0) <= 0) {
        close(fd);
        return -1;
    }
    int total = 0;
    while (total < (int)cap - 1) {
        int n = (int)recv(fd, buf + total, cap - 1 - (size_t)total, 0);
        if (n <= 0)
            break;
        total += n;
    }
    buf[total] = 0;
    close(fd);
    return total;
}

static int rtsp_probe(uint32_t ip, int port, char *out, size_t outsz)
{
    char ipbuf[16], req[256];
    u32_to_ip(ip, ipbuf);
    snprintf(req, sizeof req,
             "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: haku\r\n\r\n", ipbuf);
    char buf[2048];
    if (text_request(ip, port, req, buf, sizeof buf, 1200) <= 0)
        return -1;
    if (strncmp(buf, "RTSP/", 5) != 0)
        return -1;
    char server[80] = "";
    char *s = strcasestr(buf, "server:");
    if (s) {
        s = strchr(s, ':') + 1;
        while (*s == ' ')
            s++;
        size_t l = strcspn(s, "\r\n");
        if (l >= sizeof server)
            l = sizeof server - 1;
        memcpy(server, s, l);
        server[l] = 0;
    }
    if (server[0])
        snprintf(out, outsz, "RTSP:%d %s", port, server);
    else
        snprintf(out, outsz, "RTSP:%d", port);
    return 0;
}

static void xml_grab(const char *buf, const char *tag, char *out, size_t outsz)
{
    out[0] = 0;
    const char *p = strcasestr(buf, tag);
    if (!p)
        return;
    p = strchr(p, '>');
    if (!p)
        return;
    p++;
    const char *e = strchr(p, '<');
    if (!e)
        return;
    size_t l = (size_t)(e - p);
    if (l >= outsz)
        l = outsz - 1;
    memcpy(out, p, l);
    out[l] = 0;
}

static int onvif_probe(uint32_t ip, int port, char *out, size_t outsz)
{
    char ipbuf[16], req[1024];
    u32_to_ip(ip, ipbuf);
    const char *body =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
        "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"
        "</s:Body></s:Envelope>";
    snprintf(req, sizeof req,
             "POST /onvif/device_service HTTP/1.0\r\nHost: %s\r\n"
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             ipbuf, strlen(body), body);
    char buf[8192];
    if (text_request(ip, port, req, buf, sizeof buf, 1800) <= 0)
        return -1;

    char man[64], model[64];
    xml_grab(buf, "Manufacturer>", man, sizeof man);
    xml_grab(buf, "Model>", model, sizeof model);
    if (man[0] || model[0]) {
        snprintf(out, outsz, "ONVIF:%d %s%s%s", port, man,
                 (man[0] && model[0]) ? " " : "", model);
        return 0;
    }
    if (strcasestr(buf, "NotAuthorized") || strcasestr(buf, "WS-Security") ||
        strstr(buf, " 401 "))
        snprintf(out, outsz, "ONVIF:%d 需认证", port);
    else
        return -1;
    return 0;
}

static int cam_keyword(uint32_t ip, int port, char *out, size_t outsz)
{
    char ipbuf[16], req[256];
    u32_to_ip(ip, ipbuf);
    snprintf(req, sizeof req,
             "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: haku\r\nConnection: close\r\n\r\n",
             ipbuf);
    char buf[4096];
    if (text_request(ip, port, req, buf, sizeof buf, 1500) <= 0)
        return -1;
    static const char *kw[] = {"Dahua",     "Hikvision", "HIKVISION", "IP Camera",
                               "IPCam",     "ONVIF",     "Hipcam",    "Uniview",
                               "TVT",       "NVR",       "DVR",       "webcamXP",
                               "GoAhead-Webs", "NetSurveillance"};
    for (size_t i = 0; i < sizeof kw / sizeof kw[0]; i++) {
        if (strcasestr(buf, kw[i])) {
            snprintf(out, outsz, "HTTP:%d %s", port, kw[i]);
            return 0;
        }
    }
    return -1;
}

static void camera_check(host_t *h)
{
    char ev[160];
    if (has_port(h, 554) && rtsp_probe(h->ip, 554, ev, sizeof ev) == 0)
        cam_append(h, "%s", ev);
    if (has_port(h, 8554) && rtsp_probe(h->ip, 8554, ev, sizeof ev) == 0)
        cam_append(h, "%s", ev);
    if (has_port(h, 37777))
        cam_append(h, "端口 37777（大华 SDK）");
    if (has_port(h, 34567))
        cam_append(h, "端口 34567（XMeye）");

    static const int web[] = {80, 8080, 8000, 8001, 81, 88, 8008};
    int tried = 0;
    for (size_t i = 0; i < sizeof web / sizeof web[0] && tried < 2; i++) {
        if (!has_port(h, web[i]))
            continue;
        tried++;
        if (onvif_probe(h->ip, web[i], ev, sizeof ev) == 0)
            cam_append(h, "%s", ev);
        else if (cam_keyword(h->ip, web[i], ev, sizeof ev) == 0)
            cam_append(h, "%s", ev);
    }
}

/* WS-Discovery：海康/大华这类 ONVIF 摄像头会回 ProbeMatch */
static void *wsd_thread(void *arg)
{
    labeltab_t *tab = arg;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return NULL;
    int ttl = 2;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);

    const char *msg =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\""
        " xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
        " xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\""
        " xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
        "<e:Header><w:MessageID>uuid:5c0e1c2a-9d61-4a3b-8f7e-1b2c3d4e5f60</w:MessageID>"
        "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
        "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
        "</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "</d:Probe></e:Body></e:Envelope>";

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(3702);
    inet_pton(AF_INET, "239.255.255.250", &dst.sin_addr);
    sendto(fd, msg, strlen(msg), 0, (struct sockaddr *)&dst, sizeof dst);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    char buf[4096];
    while (ms_since(&t0) < 3000) {
        struct pollfd p = {fd, POLLIN, 0};
        int left = 3000 - ms_since(&t0);
        if (left > 300)
            left = 300;
        if (poll(&p, 1, left) <= 0)
            continue;
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0)
            break;
        buf[n] = 0;
        uint32_t ip = ntohl(from.sin_addr.s_addr);

        char addrs[96];
        xml_grab(buf, "XAddrs>", addrs, sizeof addrs);
        char label[160];
        if (strcasestr(buf, "NetworkVideoTransmitter"))
            snprintf(label, sizeof label, "WS-Discovery 摄像头%s%s",
                     addrs[0] ? " " : "", addrs);
        else
            snprintf(label, sizeof label, "WS-Discovery 设备%s%s",
                     addrs[0] ? " " : "", addrs);
        labeltab_add(tab, ip, label);
    }
    close(fd);
    return NULL;
}

/* ---------------------------------------------------------------- 无线勘查 */

typedef struct {
    char ssid[64];
    char bssid[20];
    int freq;
    int rssi;
    char caps[192];
} ap_t;

static ap_t g_aps[128];
static int g_naps;

static int json_field_str(const char *obj, const char *key, char *out, size_t n)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(obj, pat);
    if (!p)
        return 0;
    p += strlen(pat);
    const char *c = strchr(p, ':');
    if (!c)
        return 0;
    p = c + 1;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    if (*p != '"')
        return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < n) {
        if (*p == '\\' && p[1])
            p++;
        out[i++] = *p++;
    }
    out[i] = 0;
    return 1;
}

static int json_field_int(const char *obj, const char *key, int *out)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(obj, pat);
    if (!p)
        return 0;
    const char *c = strchr(p, ':');
    if (!c)
        return 0;
    *out = atoi(c + 1);
    return 1;
}

static int freq_to_chan(int f)
{
    if (f >= 2412 && f <= 2484)
        return f == 2484 ? 14 : (f - 2407) / 5;
    if (f >= 4900 && f <= 5925)
        return (f - 5000) / 5;
    return 0;
}

static const char *enc_label(const char *caps)
{
    if (strstr(caps, "WPA3"))
        return "WPA3";
    if (strstr(caps, "WPA2"))
        return "WPA2";
    if (strstr(caps, "WPA1") || strstr(caps, "WPA-"))
        return "WPA";
    if (strstr(caps, "WEP"))
        return "WEP";
    return "开放";
}

static int looks_like_cam(const char *ssid)
{
    char low[64];
    size_t i = 0;
    for (; ssid[i] && i < sizeof low - 1; i++)
        low[i] = (char)tolower((unsigned char)ssid[i]);
    low[i] = 0;
    static const char *kw[] = {"ipc",  "ipcam", "dvr",    "nvr",   "esp",
                               "tuya", "hik",   "dahua",  "onvif", "rtsp",
                               "camera", "cam-", "-cam",  "cam_"};
    for (size_t k = 0; k < sizeof kw / sizeof kw[0]; k++)
        if (strstr(low, kw[k]))
            return 1;
    return 0;
}

static const struct {
    const char *prefix;
    const char *vendor;
} OUI[] = {
    {"24:0a:c4", "Espressif"}, {"30:ae:a4", "Espressif"},
    {"5c:cf:7f", "Espressif"}, {"84:f3:eb", "Espressif"},
    {"44:19:b6", "Hikvision"}, {"c0:56:e3", "Hikvision"},
    {"3c:ef:8c", "Dahua"},
};

static const char *oui_vendor(const char *bssid)
{
    char key[9];
    int o = 0;
    for (const char *s = bssid; *s && o < 8; s++) {
        if (*s == ':' || *s == '-')
            continue;
        key[o++] = (char)tolower((unsigned char)*s);
        if ((o == 2 || o == 5) && o < 8)
            key[o++] = ':';
    }
    key[8] = 0;
    for (size_t i = 0; i < sizeof OUI / sizeof OUI[0]; i++)
        if (strcmp(key, OUI[i].prefix) == 0)
            return OUI[i].vendor;
    return "";
}

static int cmp_ap(const void *a, const void *b)
{
    const ap_t *x = a, *y = b;
    return y->rssi - x->rssi;
}

static int wifi_gather_termux(void)
{
    FILE *pp = popen("termux-wifi-scaninfo 2>/dev/null", "r");
    if (!pp)
        return 0;
    size_t cap = 1u << 18, len = 0;
    char *json = malloc(cap);
    if (!json) {
        pclose(pp);
        return -1;
    }
    size_t got;
    while (len + 1 < cap && (got = fread(json + len, 1, cap - 1 - len, pp)) > 0)
        len += got;
    json[len] = 0;
    pclose(pp);

    g_naps = 0;
    const char *p = json;
    while (*p && g_naps < (int)(sizeof g_aps / sizeof g_aps[0])) {
        const char *s = strchr(p, '{');
        if (!s)
            break;
        const char *e = strchr(s, '}');
        if (!e)
            break;
        size_t l = (size_t)(e - s) + 1;
        char obj[1024];
        if (l >= sizeof obj)
            l = sizeof obj - 1;
        memcpy(obj, s, l);
        obj[l] = 0;

        ap_t *ap = &g_aps[g_naps];
        memset(ap, 0, sizeof *ap);
        json_field_str(obj, "ssid", ap->ssid, sizeof ap->ssid);
        json_field_str(obj, "bssid", ap->bssid, sizeof ap->bssid);
        json_field_str(obj, "capabilities", ap->caps, sizeof ap->caps);
        json_field_int(obj, "frequency_mhz", &ap->freq);
        json_field_int(obj, "rssi", &ap->rssi);
        if (ap->bssid[0] || ap->ssid[0])
            g_naps++;
        p = e + 1;
    }
    free(json);
    return g_naps;
}

/* NetworkManager（桌面 Ubuntu 常见）。SIGNAL 是 0-100 的质量值，这里折算成 dBm */
static void nmcli_set(ap_t *cur, const char *k, const char *v)
{
    if (strcmp(k, "SSID") == 0) {
        snprintf(cur->ssid, sizeof cur->ssid, "%s", v);
    } else if (strcmp(k, "BSSID") == 0) {
        snprintf(cur->bssid, sizeof cur->bssid, "%s", v);
    } else if (strcmp(k, "FREQ") == 0) {
        cur->freq = atoi(v);
    } else if (strcmp(k, "SIGNAL") == 0) {
        int q = atoi(v);
        cur->rssi = (q > 0 && q <= 100) ? q / 2 - 100 : q;
    } else if (strcmp(k, "SECURITY") == 0) {
        if (strcmp(v, "--") != 0)
            snprintf(cur->caps, sizeof cur->caps, "%s", v);
    }
}

static int wifi_gather_nmcli(void)
{
    FILE *pp = popen("nmcli -m multiline -f SSID,BSSID,FREQ,SIGNAL,SECURITY "
                     "dev wifi list 2>/dev/null", "r");
    if (!pp)
        return 0;
    int maxap = (int)(sizeof g_aps / sizeof g_aps[0]);
    ap_t cur;
    memset(&cur, 0, sizeof cur);
    int have = 0;
    char line[512];
    while (fgets(line, sizeof line, pp)) {
        size_t l = strlen(line);
        while (l && (line[l - 1] == '\n' || line[l - 1] == '\r'))
            line[--l] = 0;
        if (!l) {
            if (have && (cur.ssid[0] || cur.bssid[0]) && g_naps < maxap)
                g_aps[g_naps++] = cur;
            memset(&cur, 0, sizeof cur);
            have = 0;
            continue;
        }
        have = 1;
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = 0;
        nmcli_set(&cur, line, colon + 1);
    }
    if (have && (cur.ssid[0] || cur.bssid[0]) && g_naps < maxap)
        g_aps[g_naps++] = cur;
    pclose(pp);
    return g_naps;
}

/* iw 兜底：先找无线接口，再 scan（很多发行版要 root 才让扫） */
static int wifi_gather_iw(void)
{
    FILE *pp = popen("iw dev 2>/dev/null", "r");
    if (!pp)
        return 0;
    char ifname[32] = "";
    char line[256];
    while (fgets(line, sizeof line, pp)) {
        char *p = strstr(line, "Interface ");
        if (p) {
            sscanf(p + 10, "%31s", ifname);
            break;
        }
    }
    pclose(pp);
    if (!ifname[0])
        return 0;

    char cmd[160];
    snprintf(cmd, sizeof cmd, "iw dev %s scan 2>/dev/null", ifname);
    pp = popen(cmd, "r");
    if (!pp)
        return 0;
    int maxap = (int)(sizeof g_aps / sizeof g_aps[0]);
    ap_t cur;
    memset(&cur, 0, sizeof cur);
    int in_bss = 0;
    while (fgets(line, sizeof line, pp)) {
        char *p;
        if (strncmp(line, "BSS ", 4) == 0) {
            if (in_bss && (cur.ssid[0] || cur.bssid[0]) && g_naps < maxap)
                g_aps[g_naps++] = cur;
            memset(&cur, 0, sizeof cur);
            in_bss = 1;
            sscanf(line + 4, "%19s", cur.bssid);
            size_t l = strlen(cur.bssid);
            if (l && cur.bssid[l - 1] == ':')
                cur.bssid[l - 1] = 0;
            continue;
        }
        if ((p = strstr(line, "freq:")))
            cur.freq = atoi(p + 5);
        else if ((p = strstr(line, "signal:")))
            cur.rssi = (int)strtod(p + 7, NULL);
        else if ((p = strstr(line, "SSID:")))
            snprintf(cur.ssid, sizeof cur.ssid, "%s", p + 5);
        else if (strstr(line, "RSN:") || strstr(line, "WPA:"))
            snprintf(cur.caps, sizeof cur.caps, "WPA2");
    }
    if (in_bss && (cur.ssid[0] || cur.bssid[0]) && g_naps < maxap)
        g_aps[g_naps++] = cur;
    pclose(pp);
    return g_naps;
}

/* 一个 AP 的备注串：开放/WPS/厂商/疑似摄像头 */
static void ap_note(const ap_t *ap, char *note, size_t cap)
{
    note[0] = 0;
    if (strcmp(enc_label(ap->caps), "开放") == 0)
        snprintf(note, cap, "开放");
    if (strstr(ap->caps, "WPS"))
        snprintf(note + strlen(note), cap - strlen(note), "%sWPS", note[0] ? " · " : "");
    const char *vend = oui_lookup(ap->bssid); /* 有完整 OUI 库就用它 */
    if (!vend[0])
        vend = oui_vendor(ap->bssid); /* 否则退回内置小表 */
    if (vend[0])
        snprintf(note + strlen(note), cap - strlen(note), "%s厂商: %.40s",
                 note[0] ? " · " : "", vend);
    if (ap->ssid[0] && looks_like_cam(ap->ssid))
        snprintf(note + strlen(note), cap - strlen(note), "%s疑似摄像头",
                 note[0] ? " · " : "");
}

static int wifi_survey(void)
{
    g_naps = 0;
    if (wifi_gather_termux() == 0 && wifi_gather_nmcli() == 0)
        wifi_gather_iw();

    if (g_naps == 0) {
        printf("周边无线：没读到（Termux 要 termux-api + 定位权限；"
               "Linux 需要 nmcli 或 iw，且要有无线网卡）。\n");
        return 0;
    }
    qsort(g_aps, (size_t)g_naps, sizeof g_aps[0], cmp_ap);

    int opens = 0;
    for (int i = 0; i < g_naps; i++)
        if (strcmp(enc_label(g_aps[i].caps), "开放") == 0)
            opens++;
    printf("周边无线 %d 个（开放 %d 个）\n\n", g_naps, opens);

    int W = term_width();
    int wide = W >= 96;
    const int WSSID = 26, WENC = 8, WSIG = 9, WCH = 5, WBAND = 7, WBSS = 19;
    int wnote = W - (WSSID + WENC + WSIG + WCH + WBAND + WBSS);
    if (wnote < 20)
        wnote = 20;

    if (wide) {
        put_cell("SSID", WSSID);
        put_cell("加密", WENC);
        put_cell("信号", WSIG);
        put_cell("信道", WCH);
        put_cell("频段", WBAND);
        put_cell("BSSID", WBSS);
        printf("备注\n");
        for (int i = 0; i < WSSID + WENC + WSIG + WCH + WBAND + WBSS + wnote; i++)
            putchar('-');
        printf("\n");
    }

    for (int i = 0; i < g_naps; i++) {
        ap_t *ap = &g_aps[i];
        char note[200];
        ap_note(ap, note, sizeof note);
        int c = freq_to_chan(ap->freq);
        const char *band = ap->freq >= 4900 ? (ap->freq >= 5925 ? "6G" : "5G") : "2.4G";

        if (wide) {
            char ssid[80], sig[16], chs[8];
            snprintf(ssid, sizeof ssid, "%.79s", ap->ssid[0] ? ap->ssid : "(隐藏 SSID)");
            snprintf(sig, sizeof sig, "%ddBm", ap->rssi);
            snprintf(chs, sizeof chs, "%d", c);
            put_cell(ssid, WSSID);
            put_cell(enc_label(ap->caps), WENC);
            put_cell(sig, WSIG);
            put_cell(chs, WCH);
            put_cell(band, WBAND);
            put_cell(ap->bssid, WBSS);
            put_cell(note, wnote);
            printf("\n");
        } else {
            /* 窄屏（手机）：两行一个 SSID，第二行放 BSSID 与备注 */
            int wssid = W - 21;
            if (wssid < 8)
                wssid = 8;
            char ssidfit[128], line[256];
            fit_copy(ssidfit, sizeof ssidfit,
                     ap->ssid[0] ? ap->ssid : "(隐藏 SSID)", wssid);
            snprintf(line, sizeof line, "%s  %s %ddBm %d/%s", ssidfit,
                     enc_label(ap->caps), ap->rssi, c, band);
            put_fit(line, W);
            printf("\n  ");
            put_cell(ap->bssid, 18);
            put_fit(note, W > 22 ? W - 20 : 2);
            printf("\n");
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- 显示 */

static size_t utf8_seq(unsigned char c)
{
    if (c < 0x80)
        return 1;
    if ((c & 0xE0) == 0xC0)
        return 2;
    if ((c & 0xF0) == 0xE0)
        return 3;
    if ((c & 0xF8) == 0xF0)
        return 4;
    return 1;
}

static int cp_width(const unsigned char *p)
{
    unsigned int cp = 0;
    size_t n = utf8_seq(*p);
    if (n == 1)
        cp = p[0];
    else if (n == 2)
        cp = ((unsigned)(p[0] & 0x1F) << 6) | (p[1] & 0x3F);
    else if (n == 3)
        cp = ((unsigned)(p[0] & 0x0F) << 12) | ((unsigned)(p[1] & 0x3F) << 6) | (p[2] & 0x3F);
    else
        cp = ((unsigned)(p[0] & 0x07) << 18) | ((unsigned)(p[1] & 0x3F) << 12) |
             ((unsigned)(p[2] & 0x3F) << 6) | (p[3] & 0x3F);
    if (cp < 0x20)
        return 0;
    if (cp < 0x7F)
        return 1;
    if (cp < 0xA0)
        return 0;
    if (cp >= 0x1100 &&
        (cp <= 0x115F || (cp >= 0x2E80 && cp <= 0xA4CF) || (cp >= 0xAC00 && cp <= 0xD7A3) ||
         (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE6F) ||
         (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) ||
         (cp >= 0x1F300 && cp <= 0x1FAFF) || (cp >= 0x20000 && cp <= 0x3FFFD)))
        return 2;
    return 1;
}

static void put_cell(const char *s, int width)
{
    int used = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p && used < width) {
        size_t n = utf8_seq(*p);
        int w = cp_width(p);
        if (used + w > width)
            break;
        fwrite(p, 1, n, stdout);
        used += w;
        p += n;
    }
    while (used < width) {
        putchar(' ');
        used++;
    }
}

static void put_fit(const char *s, int width)
{
    int used = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p && used < width) {
        size_t n = utf8_seq(*p);
        int w = cp_width(p);
        if (used + w > width)
            break;
        fwrite(p, 1, n, stdout);
        used += w;
        p += n;
    }
}

static int has_port(const host_t *h, int port)
{
    for (int i = 0; i < h->nports; i++)
        if (h->ports[i] == port)
            return 1;
    return 0;
}

static const char *device_guess(const host_t *h)
{
    if (has_port(h, 62078))
        return "Apple 设备";
    if (has_port(h, 5555))
        return "Android(adb)";
    if (has_port(h, 631) || has_port(h, 9100))
        return "打印机";
    if (has_port(h, 3389))
        return "Windows";
    if (has_port(h, 8123) || has_port(h, 1883))
        return "智能家居";
    if (has_port(h, 445) || has_port(h, 139))
        return "NAS/SMB";
    if (has_port(h, 554) || has_port(h, 8554) || has_port(h, 37777) || has_port(h, 34567))
        return "摄像头 / NVR";
    if (h->ttl > 200)
        return "网络设备";
    if (h->ttl > 100 && h->ttl <= 128)
        return "Windows";
    if (has_port(h, 22) || has_port(h, 80) || has_port(h, 443))
        return "Linux / IoT";
    return "";
}

static int term_width(void)
{
    const char *c0 = getenv("COLUMNS");
    if (c0 && *c0) {
        int v0 = atoi(c0);
        if (v0 > 20)
            return v0;
    }
    if (!isatty(STDOUT_FILENO))
        return 120; /* 被重定向/管道时按宽布局输出，一行一台好过滤 */
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 20)
        return ws.ws_col;
    const char *c = getenv("COLUMNS");
    if (c && *c) {
        int v = atoi(c);
        if (v > 20)
            return v;
    }
    return 80;
}

/* 一台设备的说明串：识别 + MAC/厂商 + Web 指纹 + mDNS 标签 */
static void host_note(const host_t *h, char *note, size_t cap)
{
    note[0] = 0;
    const char *g = device_guess(h);
    if (*g)
        snprintf(note, cap, "%s", g);
    if (h->mac[0])
        snprintf(note + strlen(note), cap - strlen(note), "%sMAC %s%s%s",
                 note[0] ? " · " : "", h->mac, h->vendor[0] ? " " : "", h->vendor);
    if (h->banner[0])
        snprintf(note + strlen(note), cap - strlen(note), "%s%s",
                 note[0] ? " · " : "", h->banner);
    if (h->nlabels)
        snprintf(note + strlen(note), cap - strlen(note), "%s%s",
                 note[0] ? " · " : "", h->labels[0]);
    if (!h->has_icmp)
        snprintf(note + strlen(note), cap - strlen(note), "%s[仅端口响应]",
                 note[0] ? " · " : "");
}

static void render(host_t **alive, int n, const char *own, const char *subnet, int probed,
                   double elapsed)
{
    int W = term_width();
    if (W > 200)
        W = 200;
    int wide = W >= 100;

    if (wide)
        printf("本机 %s  网段 %s  在线 %d/%d  %.1fs\n\n", own, subnet, n, probed, elapsed);
    else
        printf("本机 %s\n网段 %s  在线 %d/%d  %.1fs\n\n", own, subnet, n, probed, elapsed);

    const int WIP = 15, WNAME = 22, WRTT = 8, WPORT = 23;
    int wnote = W - (WIP + WNAME + WRTT + WPORT);
    if (wnote < 24)
        wnote = 24;

    if (wide) {
        put_cell("IP", WIP);
        put_cell("名称", WNAME);
        put_cell("延迟", WRTT);
        put_cell("端口", WPORT);
        printf("说明\n");
        for (int i = 0; i < WIP + WNAME + WRTT + WPORT + wnote; i++)
            putchar('-');
        printf("\n");
    }

    for (int i = 0; i < n; i++) {
        host_t *h = alive[i];
        char ipbuf[16], rttbuf[24], portbuf[512], name[160], note[512];
        u32_to_ip(h->ip, ipbuf);
        rttbuf[0] = 0;
        if (h->rtt > 0)
            snprintf(rttbuf, sizeof rttbuf, "%.1fms", h->rtt);
        portbuf[0] = 0;
        for (int k = 0; k < h->nports; k++) {
            char tmp[16];
            snprintf(tmp, sizeof tmp, "%s%d", k ? "," : "", h->ports[k]);
            if (strlen(portbuf) + strlen(tmp) < sizeof portbuf - 1)
                strcat(portbuf, tmp);
        }
        if (!portbuf[0])
            snprintf(portbuf, sizeof portbuf, "-");

        snprintf(name, sizeof name, "%s", h->name[0] ? h->name : "-");

        host_note(h, note, sizeof note);

        if (own[0] && strcmp(ipbuf, own) == 0) {
            char tmp[192];
            snprintf(tmp, sizeof tmp, "%.160s [本机]",
                     name[0] && strcmp(name, "-") ? name : "");
            copy_str(name, sizeof name, tmp);
        }

        if (wide) {
            put_cell(ipbuf, WIP);
            put_cell(name, WNAME);
            put_cell(rttbuf[0] ? rttbuf : "-", WRTT);
            put_cell(portbuf, WPORT);
            put_cell(note, wnote);
            printf("\n");
        } else {
            /* 窄屏（手机）：一台设备一块，每行都不超过屏宽 */
            int wname = W - WIP - 8;
            if (wname < 6)
                wname = 6;
            if (i > 0)
                printf("\n");
            put_cell(ipbuf, WIP);
            put_fit(name, wname);
            if (rttbuf[0]) {
                printf(" ");
                put_fit(rttbuf, 7);
            }
            printf("\n");
            printf("  ");
            put_fit(portbuf, W - 2);
            printf("\n");
            if (note[0]) {
                printf("  ");
                put_fit(note, W - 2);
                printf("\n");
            }
        }
    }

    int ncam = 0;
    for (int i = 0; i < n; i++)
        if (alive[i]->is_cam)
            ncam++;
    if (ncam > 0) {
        printf("疑似摄像头（%d）\n", ncam);
        for (int i = 0; i < n; i++) {
            if (!alive[i]->is_cam)
                continue;
            char ipbuf[16];
            u32_to_ip(alive[i]->ip, ipbuf);
            if (wide) {
                printf("  %-15s %s\n", ipbuf, alive[i]->cam);
            } else {
                put_cell(ipbuf, WIP);
                put_fit(alive[i]->cam, W - WIP - 2);
                printf("\n");
            }
        }
        printf("\n");
    }
}

static void json_escape(const char *s, char *out, size_t outsz)
{
    size_t o = 0;
    for (; *s && o + 3 < outsz; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c < 0x20) {
            o += (size_t)snprintf(out + o, outsz - o, "\\u%04x", c);
        } else {
            out[o++] = (char)c;
        }
    }
    out[o] = 0;
}

static int write_json(const char *path, host_t **alive, int n, const char *own,
                      const char *subnet, double elapsed)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    char when[64];
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);
    strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%S%z", &tmv);

    char eo[256];
    json_escape(own, eo, sizeof eo);
    fprintf(f, "{\n  \"scanned_at\": \"%s\",\n  \"local_ip\": \"%s\",\n"
               "  \"subnet\": \"%s\",\n  \"elapsed_s\": %.2f,\n  \"hosts\": [\n",
            when, eo, subnet, elapsed);

    for (int i = 0; i < n; i++) {
        host_t *h = alive[i];
        char ipbuf[16], en[300], eb[400], el[200];
        u32_to_ip(h->ip, ipbuf);
        json_escape(h->name, en, sizeof en);
        json_escape(h->banner, eb, sizeof eb);

        char ports[512] = "";
        for (int k = 0; k < h->nports; k++) {
            char tmp[16];
            snprintf(tmp, sizeof tmp, "%s%d", k ? ", " : "", h->ports[k]);
            strcat(ports, tmp);
        }
        char labels[1024] = "";
        for (int k = 0; k < h->nlabels; k++) {
            json_escape(h->labels[k], el, sizeof el);
            strcat(labels, k ? ", " : "");
            strcat(labels, "\"");
            strcat(labels, el);
            strcat(labels, "\"");
        }
        char ec[520];
        json_escape(h->cam, ec, sizeof ec);
        fprintf(f,
                "    {\"ip\": \"%s\", \"name\": \"%s\", \"alive_by\": [\"%s\"%s%s], "
                "\"rtt_ms\": %.2f, \"ttl\": %d, \"ports\": [%s], \"banner\": \"%s\", "
                "\"labels\": [%s], \"guess\": \"%s\", \"mac\": \"%s\", \"vendor\": \"%s\", "
                "\"camera\": %s, \"camera_evidence\": \"%s\"}%s\n",
                ipbuf, en, h->has_icmp ? "icmp" : "tcp",
                h->nports ? ", \"tcp\"" : "", "",
                h->rtt, h->ttl, ports, eb, labels, device_guess(h),
                h->mac, h->vendor, h->is_cam ? "true" : "false", ec,
                i + 1 < n ? "," : "");
    }
    fprintf(f, "  ]");
    if (g_naps > 0) {
        fprintf(f, ",\n  \"wifi\": [\n");
        for (int i = 0; i < g_naps; i++) {
            char es[200], eb2[400];
            json_escape(g_aps[i].ssid, es, sizeof es);
            json_escape(g_aps[i].caps, eb2, sizeof eb2);
            fprintf(f,
                    "    {\"ssid\": \"%s\", \"bssid\": \"%s\", \"rssi\": %d, "
                    "\"freq_mhz\": %d, \"channel\": %d, \"enc\": \"%s\", \"caps\": \"%s\", "
                    "\"open\": %s, \"camera_like\": %s}%s\n",
                    es, g_aps[i].bssid, g_aps[i].rssi, g_aps[i].freq,
                    freq_to_chan(g_aps[i].freq), enc_label(g_aps[i].caps), eb2,
                    strcmp(enc_label(g_aps[i].caps), "开放") == 0 ? "true" : "false",
                    looks_like_cam(g_aps[i].ssid) ? "true" : "false",
                    i + 1 < g_naps ? "," : "");
        }
        fprintf(f, "  ]");
    }
    fprintf(f, "\n}\n");
    fclose(f);
    return 0;
}

/* ---------------------------------------------------------------- 并行 */

static uint32_t *g_t;
static int g_nt;
static host_t *g_slots;
static int g_cursor;
static int g_timeout_ms = 700;
static int g_live_ms = 400;
static const int *g_ports;
static int g_nports;
static int g_no_http;
static int g_no_cam;

static void *ping_worker(void *arg)
{
    (void)arg;
    for (;;) {
        int i = __atomic_fetch_add(&g_cursor, 1, __ATOMIC_RELAXED);
        if (i >= g_nt)
            break;
        double rtt;
        int ttl;
        if (ping_once(g_t[i], &rtt, &ttl)) {
            g_slots[i].has_icmp = 1;
            g_slots[i].alive = 1;
            g_slots[i].rtt = rtt;
            g_slots[i].ttl = ttl;
        }
    }
    return NULL;
}

static void *live_worker(void *arg)
{
    (void)arg;
    for (;;) {
        int i = __atomic_fetch_add(&g_cursor, 1, __ATOMIC_RELAXED);
        if (i >= g_nt)
            break;
        if (g_slots[i].alive)
            continue;
        int openp[16];
        int n = scan_ports(g_t[i], LIVE_PORTS, NLIVE, g_live_ms, openp, 16);
        if (n > 0) {
            g_slots[i].alive = 1;
            g_slots[i].nports = n;
            for (int k = 0; k < n; k++)
                g_slots[i].ports[k] = openp[k];
        }
    }
    return NULL;
}

static void *full_worker(void *arg)
{
    (void)arg;
    for (;;) {
        int i = __atomic_fetch_add(&g_cursor, 1, __ATOMIC_RELAXED);
        if (i >= g_nt)
            break;
        host_t *h = &g_slots[i];
        if (!h->alive)
            continue;
        h->ip = g_t[i];
        if (h->nports == 0 && g_nports > 0)
            h->nports = scan_ports(g_t[i], g_ports, g_nports, g_timeout_ms, h->ports, MAXPORTS);
        rdns(g_t[i], h->name, sizeof h->name);
        if (!g_no_http) {
            for (int k = 0; k < NHTTP; k++) {
                if (!has_port(h, HTTP_PORTS[k].port))
                    continue;
                if (http_banner(g_t[i], HTTP_PORTS[k].port, HTTP_PORTS[k].tls, h->banner,
                                sizeof h->banner) == 0)
                    break;
            }
        }
        if (!g_no_cam)
            camera_check(h);
    }
    return NULL;
}

static void run_workers(void *(*fn)(void *), int nthreads, uint32_t *targets, int nt,
                        host_t *slots)
{
    g_t = targets;
    g_nt = nt;
    g_slots = slots;
    g_cursor = 0;
    if (nthreads > MAXTHREADS)
        nthreads = MAXTHREADS;
    if (nthreads < 1)
        nthreads = 1;
    if (nthreads > nt)
        nthreads = nt > 0 ? nt : 1;
    pthread_t th[MAXTHREADS];
    int created = 0;
    for (int i = 0; i < nthreads; i++)
        if (pthread_create(&th[i], NULL, fn, NULL) == 0)
            created++;
        else
            break;
    if (created == 0) {
        fn(NULL);
        return;
    }
    for (int i = 0; i < created; i++)
        pthread_join(th[i], NULL);
}

static int cmp_host(const void *a, const void *b)
{
    const host_t *ha = *(host_t *const *)a;
    const host_t *hb = *(host_t *const *)b;
    return ha->ip < hb->ip ? -1 : (ha->ip > hb->ip ? 1 : 0);
}

/* ---------------------------------------------------------------- main */

static void usage(void)
{
    printf("用法: haku [选项]\n"
           "  -t, --target <IP/CIDR/范围>  如 192.168.2.0/24、192.168.2.1-60，逗号分隔\n"
           "  -p, --ports <列表>           如 1-1024 或 22,80,443（默认内置 32 个常用端口）\n"
           "  -w, --wifi                   同时勘查周边无线（SSID/加密/信号/信道）\n"
           "      --wifi-only              只勘查无线，不扫局域网\n"
           "      --timeout <ms>           单个 TCP 连接超时（默认 700）\n"
           "      --threads <n>            并发主机数（默认 64）\n"
           "      --no-mdns                跳过 mDNS\n"
           "      --no-ssdp                跳过 SSDP/UPnP\n"
           "      --no-http                不抓 Web 标题 / Server 头\n"
           "      --no-cam                 跳过摄像头指纹（WS-Discovery/RTSP/ONVIF）\n"
           "      --json <路径>            导出 JSON\n"
           "  -h, --help                   显示本帮助\n"
           "\n仅限你拥有或已获授权的网络使用。\n");
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    const char *opt_target = NULL;
    const char *opt_ports = NULL;
    const char *opt_json = NULL;
    int threads = 64;
    int no_mdns = 0, no_ssdp = 0;
    int do_wifi = 0, wifi_only = 0;

    static const struct option longopts[] = {
        {"target", required_argument, NULL, 't'},
        {"ports", required_argument, NULL, 'p'},
        {"wifi", no_argument, NULL, 'w'},
        {"wifi-only", no_argument, NULL, 7},
        {"timeout", required_argument, NULL, 1},
        {"threads", required_argument, NULL, 2},
        {"no-mdns", no_argument, NULL, 3},
        {"no-ssdp", no_argument, NULL, 4},
        {"no-http", no_argument, NULL, 5},
        {"no-cam", no_argument, NULL, 8},
        {"json", required_argument, NULL, 6},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "t:p:wh", longopts, NULL)) != -1) {
        switch (c) {
        case 't': opt_target = optarg; break;
        case 'p': opt_ports = optarg; break;
        case 'w': do_wifi = 1; break;
        case 7: do_wifi = 1; wifi_only = 1; break;
        case 1: g_timeout_ms = atoi(optarg); break;
        case 2: threads = atoi(optarg); break;
        case 3: no_mdns = 1; break;
        case 4: no_ssdp = 1; break;
        case 5: g_no_http = 1; break;
        case 8: g_no_cam = 1; break;
        case 6: opt_json = optarg; break;
        case 'h': usage(); return 0;
        default: usage(); return 2;
        }
    }
    if (g_timeout_ms < 50)
        g_timeout_ms = 50;
    if (threads < 1)
        threads = 1;

    if (do_wifi) {
        wifi_survey();
        if (wifi_only) {
            if (opt_json && g_naps > 0) {
                FILE *jf = fopen(opt_json, "w");
                if (jf) {
                    fprintf(jf, "{\"wifi\": [\n");
                    for (int i = 0; i < g_naps; i++) {
                        char es[200], eb2[400];
                        json_escape(g_aps[i].ssid, es, sizeof es);
                        json_escape(g_aps[i].caps, eb2, sizeof eb2);
                        fprintf(jf,
                                "  {\"ssid\": \"%s\", \"bssid\": \"%s\", \"rssi\": %d, "
                                "\"freq_mhz\": %d, \"channel\": %d, \"enc\": \"%s\", "
                                "\"caps\": \"%s\", \"open\": %s, \"camera_like\": %s}%s\n",
                                es, g_aps[i].bssid, g_aps[i].rssi, g_aps[i].freq,
                                freq_to_chan(g_aps[i].freq), enc_label(g_aps[i].caps), eb2,
                                strcmp(enc_label(g_aps[i].caps), "开放") == 0 ? "true" : "false",
                                looks_like_cam(g_aps[i].ssid) ? "true" : "false",
                                i + 1 < g_naps ? "," : "");
                    }
                    fprintf(jf, "]}\n");
                    fclose(jf);
                    printf("\n已导出 %s（%d 个 SSID）\n", opt_json, g_naps);
                }
            }
            return 0;
        }
        printf("\n");
    }

    char own[16] = "-";
    char mask[16] = "255.255.255.0";
    char subnet[64] = "-";
    uint32_t *targets = NULL;
    int nt = 0;
    double t_start = now_sec();

    if (local_prefix(own, mask) < 0) {
        if (fallback_local(own) < 0)
            snprintf(own, sizeof own, "-");
        snprintf(mask, sizeof mask, "255.255.255.0");
    }

    if (opt_target) {
        nt = parse_targets(opt_target, &targets);
        snprintf(subnet, sizeof subnet, "%s", opt_target);
    } else {
        uint32_t me = 0, m = 0;
        if (!ip_to_u32(own, &me) || !ip_to_u32(mask, &m)) {
            fprintf(stderr, "拿不到本机网段，请用 -t 指定。\n");
            return 2;
        }
        uint32_t net = me & m;
        uint32_t count = (~m) + 1;
        if (count > 4096) {
            m = 0xFFFFFF00u;
            net = me & m;
            count = 256;
        }
        targets = malloc((size_t)count * sizeof *targets);
        if (!targets)
            return 2;
        for (uint32_t i = 1; i + 1 < count; i++)
            targets[nt++] = net + i;
        char netbuf[16];
        u32_to_ip(net, netbuf);
        snprintf(subnet, sizeof subnet, "%s/%d", netbuf, prefix_bits(m));
    }

    if (nt == 0) {
        fprintf(stderr, "目标为空。\n");
        return 2;
    }

    int ports_buf[MAXPORTS];
    if (opt_ports) {
        g_nports = parse_ports(opt_ports, ports_buf, MAXPORTS);
        g_ports = ports_buf;
        if (g_nports == 0) {
            fprintf(stderr, "端口列表解析不了：%s\n", opt_ports);
            return 2;
        }
    } else {
        g_nports = NDEFAULT;
        g_ports = DEFAULT_PORTS;
    }

    host_t *slots = calloc((size_t)nt, sizeof *slots);
    if (!slots) {
        fprintf(stderr, "内存不够（%d 个目标）。\n", nt);
        return 2;
    }

    static labeltab_t mtab, stab, ctab;
    pthread_t t_mdns, t_ssdp, t_wsd;
    int has_mdns = 0, has_ssdp = 0, has_wsd = 0;
    if (!no_mdns && pthread_create(&t_mdns, NULL, mdns_thread, &mtab) == 0)
        has_mdns = 1;
    if (!no_ssdp && pthread_create(&t_ssdp, NULL, ssdp_thread, &stab) == 0)
        has_ssdp = 1;
    if (!g_no_cam && pthread_create(&t_wsd, NULL, wsd_thread, &ctab) == 0)
        has_wsd = 1;

    run_workers(ping_worker, threads, targets, nt, slots);
    run_workers(live_worker, threads, targets, nt, slots);
    run_workers(full_worker, threads, targets, nt, slots);

    if (has_mdns)
        pthread_join(t_mdns, NULL);
    if (has_ssdp)
        pthread_join(t_ssdp, NULL);
    if (has_wsd)
        pthread_join(t_wsd, NULL);

    host_t **alive = malloc((size_t)nt * sizeof *alive);
    if (!alive) {
        free(slots);
        free(targets);
        return 2;
    }
    int n = 0;
    for (int i = 0; i < nt; i++) {
        if (!slots[i].alive)
            continue;
        slots[i].ip = targets[i];
        for (int k = 0; k < mtab.n; k++)
            if (mtab.v[k].ip == slots[i].ip)
                host_label_add(&slots[i], mtab.v[k].text);
        for (int k = 0; k < stab.n; k++)
            if (stab.v[k].ip == slots[i].ip)
                host_label_add(&slots[i], stab.v[k].text);
        for (int k = 0; k < ctab.n; k++)
            if (ctab.v[k].ip == slots[i].ip)
                cam_append(&slots[i], "%s", ctab.v[k].text);
        if (!slots[i].name[0] && slots[i].nlabels)
            snprintf(slots[i].name, sizeof slots[i].name, "%s", slots[i].labels[0]);
        alive[n++] = &slots[i];
    }
    qsort(alive, (size_t)n, sizeof *alive, cmp_host);

    /* Linux：ping 过之后 /proc/net/arp 里就有条目，补 MAC 再查厂商；Android 上会静默跳过 */
    for (int i = 0; i < n; i++) {
        if (arp_lookup(alive[i]->ip, alive[i]->mac, sizeof alive[i]->mac) == 0)
            snprintf(alive[i]->vendor, sizeof alive[i]->vendor, "%s",
                     oui_lookup(alive[i]->mac));
    }

    double elapsed = now_sec() - t_start;
    render(alive, n, own, subnet, nt, elapsed);

    if (opt_json) {
        if (write_json(opt_json, alive, n, own, subnet, elapsed) == 0)
            printf("\n已导出 %s（%d 台）\n", opt_json, n);
        else
            fprintf(stderr, "写不了 %s：%s\n", opt_json, strerror(errno));
    }

    int nmac = 0;
    for (int i = 0; i < n; i++)
        if (alive[i]->mac[0])
            nmac++;
    if (nmac > 0)
        printf("\n注：%d 台的 MAC 取自 %s；厂商来自本机 OUI 库（%d 条）。\n", nmac,
               getenv("HAKU_ARP_FILE") ? getenv("HAKU_ARP_FILE") : "/proc/net/arp", g_noui);
    else
        printf("\n注：读不到 ARP 表（Android 无 root 时 SELinux 会挡住），所以没有 MAC；"
               "在 Linux 上跑就能拿到。\n");

    free(mtab.v);
    free(stab.v);
    free(ctab.v);
    free(alive);
    free(slots);
    free(targets);
    return 0;
}
