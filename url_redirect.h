#ifndef _HOOK_REDIRECT_H
#define _HOOK_REDIRECT_H

int url_redirect(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, const char *url, const int len);
#endif
