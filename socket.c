#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/syscalls.h>
#include <linux/ipv6.h>
#include <linux/socket.h>

#include <linux/bottom_half.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
//#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/jiffies.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/jhash.h>
#include <linux/ipsec.h>
#include <linux/times.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <linux/random.h> 
#include <net/tcp.h>
#include <net/ndisc.h>
#include <net/inet6_hashtables.h>
#include <net/inet6_connection_sock.h>
//#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#include <net/inet_ecn.h>
#include <net/protocol.h>
#include <net/xfrm.h>
#include <net/snmp.h>
#include <net/dsfield.h>
#include <net/timewait_sock.h>
#include <net/netdma.h>
#include <net/inet_common.h>
#include <net/secure_seq.h>
//#include <net/tcp_memcontrol.h>
//#include <net/busy_poll.h> 
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
 






/* This is the structure we shall use to register our function */

#define DISABLE_WRITE_PROTECTION (write_cr0(read_cr0() & (~ 0x10000)))
#define ENABLE_WRITE_PROTECTION (write_cr0(read_cr0() | 0x10000))

static unsigned long **find_sys_call_table(void);
asmlinkage int hijackConnect(struct sock *sk, struct sockaddr *uaddr,int addr_len);

asmlinkage int (*original_sys_connect)(struct sock *, struct sockaddr *, int);
asmlinkage unsigned long **sys_call_table;

/* Initialisation routine */
int init_module(void)
{    
    sys_call_table = find_sys_call_table();   
    
    if(!sys_call_table) {
	printk(KERN_ERR "Couldn't find sys_call_table.\n");
	return -EPERM;  /* operation not permitted; couldn't find general error */
    }
    
    DISABLE_WRITE_PROTECTION;
    original_sys_connect = (void *) sys_call_table[SYS_CONNECT];
    sys_call_table[SYS_CONNECT] = (unsigned long *) hijackConnect;
    ENABLE_WRITE_PROTECTION;

    printk(KERN_INFO "Connect system call is hijacked!\n");

    return 0;
}
	
/* Cleanup routine */
void cleanup_module(void)
{
    printk(KERN_INFO "Unhook hijacking\n");

    /* Restore the original sys_open in the table */
    DISABLE_WRITE_PROTECTION;
    sys_call_table[SYS_CONNECT] = (unsigned long *) original_sys_connect;
    ENABLE_WRITE_PROTECTION;
}


static unsigned long **find_sys_call_table() {
    unsigned long offset;
    unsigned long **sct;

    for(offset = PAGE_OFFSET; offset < ULLONG_MAX; offset += sizeof(void *)) {
	sct = (unsigned long **) offset;

	if(sct[__NR_close] == (unsigned long *) sys_close)
	    return sct;
    }

    /*
     * Given the loop limit, it's somewhat unlikely we'll get here. I don't
     * even know if we can attempt to fetch such high addresses from memory,
     * and even if you can, it will take a while!
     */
    return NULL;
}

asmlinkage int hijackConnect(struct sock *sk, struct sockaddr *uaddr,int addr_len)
{
   printk(KERN_INFO "Connect is called!\n");
   
 /*  struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
   struct inet_sock *inet = inet_sk(sk);
   struct tcp_sock *tp = tcp_sk(sk);
   __be16 orig_sport, orig_dport;
   __be32 daddr, nexthop, test;

   orig_sport = inet->inet_sport;
   orig_dport = usin->sin_port;
   test = inet->inet_saddr;
   //daddr = usin->sin_addr.s_addr;

   printk(KERN_INFO "ADDRESS - %d", ntohl(test));*/
   return (*original_sys_connect)(sk,uaddr,addr_len);
}



MODULE_AUTHOR("KYI CHO | GUELOR | MICHAEL");
MODULE_DESCRIPTION("FIREWALL");
MODULE_LICENSE("GPL");

