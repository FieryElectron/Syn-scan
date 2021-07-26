#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <time.h>

unsigned csum_tcpudp_nofold(unsigned saddr, unsigned daddr, unsigned len, unsigned proto, unsigned sum)
{
    unsigned long long s = (unsigned)sum;
    s += (unsigned)saddr;
    s += (unsigned)daddr;
    s += (proto + len) << 8;
    s += (s >> 32);
    return (unsigned)s;
}

unsigned short check_sum(unsigned short *addr, int len, unsigned sum)
{
    int nleft = len;
    unsigned short *w = addr;
    unsigned short ret = 0;
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(unsigned char *)(&ret) = *(unsigned char *)w;
        sum += ret;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret = ~sum;
    return ret;
}

void sendSyn(int skfd, struct sockaddr_in *target, unsigned short desport)
{
    target->sin_port = htons(desport);

    char buf[256] = {0};
    struct ip *ip;
    struct tcphdr *tcp;
    int ip_len;
    int op_len = 12;

    ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + op_len;

    ip = (struct ip *)buf;
    ip->ip_v = IPVERSION;
    ip->ip_hl = sizeof(struct ip) >> 2;
    ip->ip_tos = 0;
    ip->ip_len = htons(ip_len);
    ip->ip_id = 0;
    ip->ip_off = 0;
    ip->ip_ttl = MAXTTL;
    ip->ip_p = IPPROTO_TCP;
    ip->ip_sum = 0;
    ip->ip_dst = target->sin_addr;

    tcp = (struct tcphdr *)(buf + sizeof(struct ip));
    tcp->source = htons(1234);
    tcp->dest = target->sin_port;
    srand(time(NULL));
    tcp->doff = (sizeof(struct tcphdr) + op_len) >> 2; // tcphdr + option
    tcp->syn = 1;
    tcp->check = 0;
    tcp->window = ntohs(14600);

    tcp->seq = random();

    ip->ip_src.s_addr = inet_addr("172.25.229.147");

    unsigned sum = csum_tcpudp_nofold(ip->ip_src.s_addr, ip->ip_dst.s_addr, sizeof(struct tcphdr) + op_len, IPPROTO_TCP, 0);
    tcp->check = check_sum((unsigned short *)tcp, sizeof(struct tcphdr) + op_len, sum);

    sendto(skfd, buf, ip_len, 0, (struct sockaddr *)target, sizeof(struct sockaddr_in));
}

int main()
{
    int skfd;
    struct sockaddr_in target;

    const int on = 1;

    bzero(&target, sizeof(struct sockaddr_in));
    target.sin_family = AF_INET;

    target.sin_addr.s_addr = inet_addr("45.33.32.156");

    if ((skfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
    {
        perror("Create Error");
        exit(1);
    }

    if (setsockopt(skfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("IP_HDRINCL failed");
        exit(1);
    }

    setuid(getpid());
    printf("Start Send Syn port 1\n");

    for (int i = 1; i < 65536; ++i)
    {
        sendSyn(skfd, &target, i);
        usleep(300);
    }
    printf("End Send Syn port 65535\n");
}
