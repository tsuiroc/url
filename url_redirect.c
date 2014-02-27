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

static packet g_pkt = NULL;

const char *url_redirect_header = 
	"HTTP/1.1 301 Moved Permanently\r\n"
	"Location: http://%s\r\n"
	"Content-Type:text/html; charset=iso-8859-1\r\n"
	"Content-length: 0\r\n"
	"Cache-control: no-cache\r\n"
	"\r\n";

struct sk_buff* tcp_alloc_packet(u32 saddr, u32 daddr, u16 sport, u16 dport,
									u32 seq, u32 ack_seq, u8 *msg, int len)
{
	struct sk_buff *skb = NULL;
	int  tcp_opt_len, total_len, eth_len, ip_len, header_len, tcp_len;
	struct tcphdr *tcph = NULL;
	struct iphdr *iph = NULL;

	tcp_opt_len = 0;
	tcp_len = len + sizeof(tcph);
	ip_len = tcp_len + sizeof(iph);
	eth_len = ip_len + ETH_HLEN;

	total_len = eth_len + NET_IP_ALIGN;
	total_len += LL_MAX_HEADER;

	header_len = total_len -len;

	skb = alloc_skb(total_len, GFP_ATOMIC);
	if(!skb)
	{
		printk("alloc skb(%02x) failed\n", total_len);
		return NULL;
	}

	skb_reserve(skb, header_len);
	skb_copy_to_linear_data(skb, msg, len);
	skb->len += len;

	skb_push(skb, sizeof(struct tcph);
	skb_reset_transport_header(skb);

	tcph = tcp_hdr(skb);

	memset(tcph, 0x00, sizeof(stru


}

static int _tcp_xmit(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, packet *p)
{
	int tcp_len = 0;
	unsigned int ack_seq = 0;
	struct sk_buff *sk = NULL;

	tcp_len = ntohs(iph->tot_len) -((iph->ihl) + (tcph->doff)) * 4;
	ack_seq = ntohl(th->seq) + tcp_len;
	ack_seq = htonl(ack_seq);

	sk = tcp_alloc_packet(iph->daddr, iph->saddr, tcph->dest, tcph->source,
							tcph->ack_seq, ack_seq, p->buf, p->len)
	if(NULL == sk)
	{
		printk("%s(%d) tcp_alloc_packet error!\n ", __FUNCTION__,__LINE__);
		return 0;
	}
								

	

}

int url_redirect(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, const char *url, const int len)
{
	int ret = 0;
	packet *p = NULL;
	
	rcu_read_lock();
	p = rcu_dereference( g_pkt);
	
	memset(p->pkt, 0x00, URL_MAX_LEN);
	memcpy(p->packet, url, len);
	p->len = len;

	_tcp_xmit(skb, iph, tcph, p);
	
 	rcu_read_unlock();
}

int url_redirect_init(void)
{
	packet *p = NULL;
	
	rcu_read_lock();
	p = rcu_dereference( g_pkt);
	
	p->pkt = kzalloc(URL_MAX_LEN, GFP_KERNEL);
	if ( unlikely( NULL == p ) )
	{  
		rcu_read_unlock();
		return 0;  
	} 
	
	memset(p->pkt, 0x00, URL_MAX_LEN);
	p->len = 0;
	
 	rcu_read_unlock();
	return 1;
}

int url_redirect_exit(void)
{
	packet *p = NULL;
	
	rcu_read_lock();
	p = rcu_dereference( g_pkt);

	if (NULL != p )
		kfree(p);

 	rcu_read_unlock();
	return 1;
}


