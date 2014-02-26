#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h> 
#include <linux/netdevice.h> 
#include <linux/skbuff.h> 
#include <linux/netfilter_ipv4.h> 
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <net/tcp.h>

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("cui peng");

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
						const struct net_device *in, 	const struct net_device *out,
						int (*okfn)(struct sk_buff *));

struct nf_hook_ops http_ops = {  
   .list =  {NULL,NULL},  
   .hook = hook_func,  
   .pf = PF_INET,  
   .hooknum = NF_INET_LOCAL_OUT, //NF_INET_PRE_ROUTING,  
   .priority = NF_IP_PRI_FILTER,  
 }; 

static int paser_get_url(unsigned char *url)
{
	unsigned char *host = url;
	
	while(*host != '\r' && *(host + 1) != '\n') host++;
	host += 2; //skip '\r'  and  '\n'
	
	if(host[0] == 'H' && host[1] == 'o' && 
		host[2] == 's' && host[3] == 't' && 
		host[4] == ':' && host[5] == ' ')
	{
		host += 6; //skip "Host:"
//temp code,which will be replace with hash-cmp function by cuipeng in future
		printk("hook a get url Host: ");
		for (host; *host != '\r' && *(host+1) != '\n'; host++)
			printk("%c",*host);
		printk("\n");
//end by cuipeng
	}


}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
						const struct net_device *in, 	const struct net_device *out,
						int (*okfn)(struct sk_buff *))
{
        struct sk_buff *sb = skb;
	 	struct iphdr *iph = ip_hdr(sb);
		struct tcphdr *tcph = tcp_hdr(sb);
		unsigned char *payload = NULL;
		int data_len,iph_len,tcph_len;
		unsigned short dest;

        switch(iph->protocol)
        {
             case IPPROTO_TCP:
				dest = ntohs(tcph->dest);
				iph_len = iph->ihl;
				tcph_len = tcph->doff;
				
				if(dest == 8080 ||dest == 80 )
				{
					payload = (unsigned char *)tcph + tcph->doff*4;					
					data_len = ntohs(iph->tot_len) - iph_len - tcph_len;

					if(payload[0] == 'G' && payload[1] == 'E' && payload[2] =='T' && payload[3] == ' ')
					{
						paser_get_url(payload);
					}

				}
				break;
#if 0
              case IPPROTO_ICMP:
                    printk(" It's a ICMP PACKET\n");break;
              case IPPROTO_UDP:
                    printk(" It's a UDP PACKET\n");break;
#endif
        }
        return NF_ACCEPT; 
}

int __init hook_http_init(void)
{ 
        printk("starting register_hook .....\n");
        nf_register_hook(&http_ops);
        printk("register_hook success!!!!\n");
        return 0;
}

void __exit hook_http_exit(void)
{
        printk("unregister_hook success!\n");
        nf_unregister_hook(&http_ops);
}

module_init(hook_http_init); 
module_exit(hook_http_exit);     



