#ifndef _HOOK_HTTP_H
#define _HOOK_HTTP_H

#define URL_MAXLEN  254

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb,
						const struct net_device *in, 	const struct net_device *out,
						int (*okfn)(struct sk_buff *));


#endif
