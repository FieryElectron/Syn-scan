//https://www.kernel.org/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>



#define NIPQUAD(addr) \
    ((unchar *)&addr)[0], \
    ((unchar *)&addr)[1], \
    ((unchar *)&addr)[2], \
    ((unchar *)&addr)[3]



unchar tar_ip[4] = {45,33,32,156};

int isTarIp(__be32 sip){
    if(tar_ip[0] == ((unchar *)&sip)[0] &&
            tar_ip[1] == ((unchar *)&sip)[1] &&
            tar_ip[2] == ((unchar *)&sip)[2] &&
            tar_ip[3] == ((unchar *)&sip)[3] ){
        return 1;
    }
    return 0;
}

uint sample(uint hooknum,struct sk_buff * skb,const struct net_device *in,const struct net_device *out,int (*okfn) (struct sk_buff *)){
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

    struct tcphdr *tcp_header;

    __be32 sip,dip;

    sip = ip_header->saddr;
    dip = ip_header->daddr;

    unsigned int src_port = 0;
    unsigned int dest_port = 0;


    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);

        if(isTarIp(sip) && tcp_header->rst == 0){
            printk(KERN_CRIT "%d.%d.%d.%d:%d ---> %d.%d.%d.%d:%d\n",NIPQUAD(sip),src_port,NIPQUAD(dip),dest_port);
        }
    }

    return NF_ACCEPT;
}

struct nf_hook_ops sample_ops = {
    .hook = (void*)sample,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER,
};

int sample_init(void) {
    nf_register_net_hook(&init_net,&sample_ops);
    return 0;
}

void sample_exit(void) {
    nf_unregister_net_hook(&init_net,&sample_ops);
}

module_init(sample_init);
module_exit(sample_exit);


