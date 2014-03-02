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
#include <linux/string.h>
#include "url_hook.h"
#include "url_paser.h"
#include "url_redirect.h"
static unsigned char *url_new = "www.126.com";

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
						while(*payload != '\r' && *(payload + 1) != '\n') payload++;
						payload += 2; //skip '\r'  and  '\n'
	
						if(url_paser(payload))
						{
							url_redirect(skb,iph,tcph, url_new, 11);					
						}
					}
				}
				break;
        }
        return NF_ACCEPT; 
}


