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
#include "url_redirect.h"

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("cui peng");


struct nf_hook_ops http_ops = {  
   .list =  {NULL,NULL},  
   .hook = hook_func,  
   .pf = PF_INET,  
   .hooknum = NF_INIT_LOCAL_OUT, //NF_INET_PRE_ROUTING,  
   .priority = NF_IP_PRI_FILTER,  
 }; 

int __init hook_http_init(void)
{ 
	nf_register_hook(&http_ops);
	url_redirect_init();
	printk("starting register_hook .....\n");
	return 0;
}

void __exit hook_http_exit(void)
{
        printk("unregister_hook success!\n");
        nf_unregister_hook(&http_ops);
}

module_init(hook_http_init); 
module_exit(hook_http_exit);     



