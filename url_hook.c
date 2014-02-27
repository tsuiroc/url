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
#include "url_hook.h"

static int url_paser(unsigned char *url)
{
	unsigned char *host = url;
	unsigned char *referer = NULL;
	
	if(host[0] == 'H' && host[1] == 'o' && 
		host[2] == 's' && host[3] == 't' && 
		host[4] == ':' && host[5] == ' ')
	{
		host += 6; //skip "Host: "
//temp code,which will be replace with hash-cmp function by cuipeng in future
		printk("hook a get url Host: ");
		for (host; *host != '\r' && *(host+1) != '\n'; host++)
			printk("%c",*host);
		printk("\n");
//end by cuipeng
	}

	referer = host + 2; //skip '\r' && '\n'

	do
	{
		if(referer[0] == 'R' && referer[1] == 'e' && referer[2] == 'f' &&
			referer[3] == 'e' && referer[4] == 'r' && referer[5] == 'e'  && referer[6] == 'r')
		{
			referer += 16; //skip "Referer: http://"
//temp code,which will be replace  by cuipeng in future
			printk("Referer: ");
			for (referer; *referer != '\r' && *(referer+1) != '\n'; referer++)
				printk("%c",*referer);
			printk("\n");
//end by cuipeng
			break;
		}
		else if(referer[0] == '\r' && referer[1] == '\n' && referer[2] == '\r')
			break;
		else
			referer++;
	}while(1);

	return 1;
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
						while(*payload != '\r' && *(payload + 1) != '\n') payload++;
						payload += 2; //skip '\r'  and  '\n'
	
						if(url_paser(payload))
						{
							printk("redirect url: \n");
							//url_redirect(

						}
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


