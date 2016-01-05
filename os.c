#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* This is the structure we shall use to register our function */
static struct nf_hook_ops nfho;
static unsigned char *http_port = "\x50";

/* This is the hook function itself */
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip_header;       // ip header struct
    struct tcphdr *tcp_header;     // tcp header struct
    unsigned int sport, dport;    
    char dest[16];
    char *data;    

    if(!skb) { 
       return NF_ACCEPT;
    }
    
    ip_header = (struct iphdr *)skb_network_header(skb);
    
    if(ip_header && (ip_header->protocol==IPPROTO_TCP))
    {
       tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
      
       if(ntohs(tcp_header->dest) == *(unsigned short *)http_port)
       {
          sport = htons((unsigned short int) tcp_header->source); //sport now has the source port
          dport = htons((unsigned short int) tcp_header->dest);   //dport now has the dest port
 
          data = (char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));       
          printk(KERN_INFO "Data - %s", data);
          snprintf(dest, 16, "%pI4", &(ip_header->daddr));
         
          if((strstr(dest,"173.194.43") != NULL)
            || (strstr(dest,"216.58.216") != NULL)
            || (strstr(dest,"209.148.199") != NULL)
            || (strstr(dest,"209.148.199") != NULL)
            || (strstr(dest,"209.148.199") != NULL)){
          
               return NF_DROP;
         }
       }
       else { 
         return NF_ACCEPT;
       }
    }         
    return NF_ACCEPT;           /* Drop ALL packets */
}

/* Initialisation routine */
int init_module(void)
{
    printk(KERN_INFO "initialize kernel module\n");
    
    /* Fill in our hook structure */
    nfho.hook = hook_func;         /* Handler function */
    nfho.hooknum  = NF_INET_POST_ROUTING;
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;   /* Make our function first */

    nf_register_hook(&nfho);
    
    return 0;
}
	
/* Cleanup routine */
void cleanup_module(void)
{
    nf_unregister_hook(&nfho);
}


