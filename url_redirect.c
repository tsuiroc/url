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
#include "url_redirect.h"

typedef struct packet_t packet;
struct packet_t{
	void * pkt;
	unsigned int len;
};

static packet *g_pkt = NULL;

const char *url_redirect_header = 
	"HTTP/1.1 301 Moved Permanently\r\n"
	"Location: http://%s\r\n"
	"Content-Type:text/html; charset=iso-8859-1\r\n"
	"Content-length: 0\r\n"
	"Cache-control: no-cache\r\n"
	"\r\n";

int skb_iphdr_init( struct sk_buff *skb, u8 protocol,
 
                    u32 saddr, u32 daddr, int ip_len )
{
    struct iphdr *iph = NULL;
	
    skb_push( skb, sizeof(struct iphdr) ); 
    skb_reset_network_header( skb );
    iph = ip_hdr( skb );
	
    iph->version  = 4;
    iph->ihl      = 5; 
    iph->tos      = 0;
    iph->tot_len  = htons(ip_len);
    iph->id       = 0;
    iph->frag_off = htons(IP_DF);
    iph->ttl      = 64;
    iph->protocol = protocol;
    iph->check    = 0;
    iph->saddr    = saddr;
    iph->daddr    = daddr;
 
    iph->check    = ip_fast_csum( ( unsigned char * )iph, iph->ihl );        
 	return 1;
}

struct sk_buff* skb_tcphdr_init(u32 saddr, u32 daddr, u16 sport, u16 dport,
									u32 seq, u32 ack_seq, u8 *msg, int len)
{
	struct sk_buff *skb = NULL;
	int  tcp_opt_len, total_len, eth_len, ip_len, header_len, tcp_len;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__wsum tcp_hdr_csum;

	tcp_len = len + sizeof(*tcph);
	ip_len = tcp_len + sizeof(*iph);
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

	skb_push(skb, sizeof(struct tcphdr));
	skb_reset_transport_header(skb);

	tcph = tcp_hdr(skb);

	memset(tcph, 0x00, sizeof(struct tcphdr));
	tcph->doff = 5;
	tcph->source = sport;
	tcph->dest = dport;
	tcph->seq = seq;
	tcph->ack_seq = ack_seq;
	tcph->urg_ptr = 0;
	tcph->psh = 0x1;
	tcph->ack = 0x1;
	tcph->window = htons(63857);
	tcph->check = 0;
	tcp_hdr_csum = csum_partial(tcph, tcp_len, 0);
	tcph->check = csum_tcpudp_magic(saddr, daddr, tcp_len,
										IPPROTO_TCP,tcp_hdr_csum);
	skb->csum = tcp_hdr_csum;

	if(tcph->check == 0)
		tcph->check = CSUM_MANGLED_0;

	skb_iphdr_init(skb, IPPROTO_TCP, saddr, daddr, ip_len);
	return skb;

}
unsigned char dest[6] = {0x20,0x6a,0x8a,0x70,0xf2,0x53};
unsigned char src[6] = {0x00,0x0c,0x29,0xad,0xb8,0xf1};

static int url_build_newpacket(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, packet *p)
{
	int tcp_len = 0;
	struct sk_buff *sk = NULL;
	struct ethhdr *eth = NULL;

	tcp_len = ntohs(iph->tot_len) - ((iph->ihl + tcph->doff) << 2);

	sk = skb_tcphdr_init(iph->daddr, iph->saddr, tcph->dest, tcph->source,
										tcph->ack_seq, tcph->seq, p->pkt, p->len);
	if(NULL == sk)
		return 0;

	eth = (struct ethhdr*)skb_push(sk, ETH_HLEN);
	if(NULL == eth)
		return 0;
	
	skb_reset_mac_header(sk);
	sk->protocol  = htons(ETH_P_IP);
    eth->h_proto    = htons(0x0800);
#if 1
    memcpy( eth->h_source, src, ETH_ALEN);
	memcpy( eth->h_dest, dest, ETH_ALEN );

	sk->dev = dev_get_by_name(&init_net, "eth1"); 
    dev_queue_xmit(sk);

#else
    memcpy( eth->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);   
    memcpy( eth->h_dest, eth_hdr(skb)->h_source, ETH_ALEN );

    if (skb->dev)
	{
		sk->dev = skb->dev;
    	dev_queue_xmit(sk); 
    }
    else
	{
		kfree_skb( sk );
		printk( "sk->dev is NULL/n" );
    }
#endif
	return 1;
}

int url_redirect(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, const char *url, const int len)
{
	return url_build_newpacket(skb, iph, tcph, g_pkt);
}

#define PATH_MAX 256 
int url_redirect_init(void)
{
	g_pkt = kzalloc(sizeof(packet), GFP_KERNEL);
	if ( unlikely( NULL == g_pkt) )
	{  
		return 0;  
	} 
	g_pkt->pkt = NULL;
	g_pkt->len = 0;

	g_pkt->pkt = kzalloc(PATH_MAX, GFP_KERNEL);
	if ( unlikely( NULL == g_pkt->pkt ) )
	{  
		return 0;  
	} 
	
	memset(g_pkt->pkt, 0x00, PATH_MAX);
	
	g_pkt->len = snprintf( g_pkt->pkt, PATH_MAX,
                    url_redirect_header,
                    "www.126.com"
                    ); 
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


