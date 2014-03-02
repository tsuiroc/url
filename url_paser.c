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
#include "url_paser.h"

static unsigned char *url_host = "www.baidu.com";
static unsigned char *url_new = "www.126.com";

static int url_host_compare(const unsigned char *host)
{
	printk("host: ");
	for(host; *host != '\r' && *(host+1) != '\n'; host++)
	{
		printk("%c",*host);
		//if(*host++ != *url_host++)
		//	return 0;
	}
	printk("\n");
	printk("url_host: %s\n", url_new);
	return 1;
}

int url_paser(unsigned char *url)
{
	unsigned char *host = url;
	unsigned char *referer = NULL;
	
	if(host[0] == 'H' && host[1] == 'o' && 
		host[2] == 's' && host[3] == 't' && 
		host[4] == ':' && host[5] == ' ')
	{
		host += 6; //skip "Host: "
		if(!url_host_compare(host))
			return 0;
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


