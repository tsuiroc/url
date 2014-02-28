#ifndef _HOOK_HTTP_H
#define _HOOK_HTTP_H

int url_redirect(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, const char *url, const int len);
#endif
