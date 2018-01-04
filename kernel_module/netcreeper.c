#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("netcreeper");
MODULE_AUTHOR("Jaskaran Veer Singh");

/*structure for firewall policies*/
struct mf_rule_desp {
    unsigned char in_out;
    char *src_ip;
    char *src_netmask;
    char *src_port;
    char *dest_ip;
    char *dest_netmask;
    char *dest_port;
    unsigned char proto;
    unsigned char action;
};

/*structure for firewall policies*/

struct mf_rule {
    unsigned char in_out;        //0: neither in nor out, 1: in, 2: out
    unsigned int src_ip;        //
    unsigned int src_netmask;        //
    unsigned int src_port;        //0~2^32
    unsigned int dest_ip;
    unsigned int dest_netmask;
    unsigned int dest_port;
    unsigned char proto;        //0: all, 1: tcp, 2: udp
    unsigned char action;        //0: for block, 1: for unblock
    struct list_head list;
};

static struct mf_rule policy_list;

//the structure used to register the function

static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

unsigned int port_str_to_int(char *port_str) {
    unsigned int port = 0;    
    int i = 0;
    if (port_str==NULL) {
        return 0;
    } 
    while (port_str[i]!='') {
        port = port*10 + (port_str[i]-'0');
        ++i;
    }
    return port;
}

unsigned int ip_str_to_hl(char *ip_str) {
    /*convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]*/
    unsigned char ip_array[4];
    int i = 0;
    unsigned int ip = 0;
    if (ip_str==NULL) {
        return 0; 
    }
    memset(ip_array, 0, 4);
    while (ip_str[i]!='.') {
        ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    //printk(KERN_INFO "ip_str_to_hl convert %s to %un", ip_str, ip);
    return ip;
}

/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/

bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
    unsigned int tmp = ntohl(ip);    //network to host long
    int cmp_len = 32;
    int i = 0, j = 0;
    printk(KERN_INFO "compare ip: %u <=> %un", tmp, ip_rule);
    if (mask != 0) {
        //printk(KERN_INFO "deal with maskn");
        //printk(KERN_INFO "mask: %d.%d.%d.%dn", mask[0], mask[1], mask[2], mask[3]);
        cmp_len = 0;
        for (i = 0; i < 32; ++i) {
            if (mask & (1 << (32-1-i)))
                cmp_len++;
            else
                break;
        }
    }
    /*compare the two IP addresses for the first cmp_len bits*/
    for (i = 31, j = 0; j < cmp_len; --i, ++j) {
        if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
            printk(KERN_INFO "ip compare: %d bit doesn't matchn", (32-i));
            return false;
        }
    }
    return true;
}

//the hook function itself: regsitered for filtering outgoing packets
//
//unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, 
//        const struct net_device *in, const struct net_device *out,
//        int (*okfn)(struct sk_buff *)) {
//
//    /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
//
//    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
//    struct udphdr *udp_header;
//    struct tcphdr *tcp_header;
//    struct list_head *p;
//    struct mf_rule *a_rule;
//    int i = 0;
//
//    /**get src and dest ip addresses**/
//
//    unsigned int src_ip = (unsigned int)ip_header->saddr;
//    unsigned int dest_ip = (unsigned int)ip_header->daddr;
//    unsigned int src_port = 0;
//    unsigned int dest_port = 0;
//
//    /***get src and dest port number***/
//
//    if (ip_header->protocol==17) {
//        udp_header = (struct udphdr *)skb_transport_header(skb);
//        src_port = (unsigned int)ntohs(udp_header->source);
//        dest_port = (unsigned int)ntohs(udp_header->dest);
//    } else if (ip_header->protocol == 6) {
//        tcp_header = (struct tcphdr *)skb_transport_header(skb);
//        src_port = (unsigned int)ntohs(tcp_header->source);
//        dest_port = (unsigned int)ntohs(tcp_header->dest);
//    }
//
//    printk(KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %un", src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 
//
//    //go through the firewall list and check if there is a match
//
//    //in case there are multiple matches, take the first one
//
//    list_for_each(p, &policy_list.list) {
//
//        i++;
//
//        a_rule = list_entry(p, struct mf_rule, list);
//        printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%un", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);
//
//        //if a rule doesn't specify as "out", skip it
//
//        if (a_rule->in_out != 2) {
//
//            printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as outn", i, a_rule->in_out);
//
//            continue;
//
//        } else {
//
//            //check the protocol
//
//            if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
//
//                printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCPn", i);
//
//                continue;
//
//            } else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
//
//                printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDPn", i);
//
//                continue;
//
//            }
//
//            //check the ip address
//
//            if (a_rule->src_ip==0) {
//
//                //rule doesn't specify ip: match
//
//            } else {
//
//                if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
//
//                    printk(KERN_INFO "rule %d not match: src ip mismatchn", i);
//
//                    continue;
//
//                }
//
//            }
//
//            if (a_rule->dest_ip == 0) {
//
//                //rule doesn't specify ip: match
//
//            } else {
//
//                if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
//
//                    printk(KERN_INFO "rule %d not match: dest ip mismatchn", i);
//
//                    continue;
//
//                }
//
//            }
//
//            //check the port number
//
//            if (a_rule->src_port==0) {
//
//                //rule doesn't specify src port: match
//
//            } else if (src_port!=a_rule->src_port) {
//
//                printk(KERN_INFO "rule %d not match: src port dismatchn", i);
//
//                continue;
//
//            }
//
//            if (a_rule->dest_port == 0) {
//
//                //rule doens't specify dest port: match
//
//            }
//
//            else if (dest_port!=a_rule->dest_port) {
//
//                printk(KERN_INFO "rule %d not match: dest port mismatchn", i);
//
//                continue;
//
//            }
//
//            //a match is found: take action
//
//            if (a_rule->action==0) {
//
//                printk(KERN_INFO "a match is found: %d, drop the packetn", i);
//
//                printk(KERN_INFO "---------------------------------------n");
//
//                return NF_DROP;
//
//            } else {
//
//                printk(KERN_INFO "a match is found: %d, accept the packetn", i);
//
//                printk(KERN_INFO "---------------------------------------n");
//
//                return NF_ACCEPT;
//
//            }
//
//        }
//
//    }
//
//    printk(KERN_INFO "no matching is found, accept the packetn");
//
//    printk(KERN_INFO "---------------------------------------n");
//
//    return NF_ACCEPT;            
//
//}


//the hook function itself: registered for filtering incoming packets

unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, 
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
    /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct list_head *p;
    struct mf_rule *a_rule;
    int i = 0;
    /**get src and dest ip addresses**/
    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned int dest_ip = (unsigned int)ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;
    /***get src and dest port number***/
    if (ip_header->protocol==17) {
        udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
        src_port = (unsigned int)ntohs(udp_header->source);
        dest_port = (unsigned int)ntohs(udp_header->dest);
    } else if (ip_header->protocol == 6) {
        tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
        src_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
    }
    printk(KERN_INFO "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %un", src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 
    //go through the firewall list and check if there is a match
    //in case there are multiple matches, take the first one
    list_for_each(p, &policy_list.list) {
        i++;
        a_rule = list_entry(p, struct mf_rule, list);
        printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%un", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);
        //if a rule doesn't specify as "in", skip it
        if (a_rule->in_out != 1) {
            printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as inn", i, a_rule->in_out);
            continue;
        } else {
            //check the protocol
            if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
                printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCPn", i);
                continue;
            } else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
                printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDPn", i);
                continue;
            }
            //check the ip address
            if (a_rule->src_ip==0) {
                //
            } else {
                if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
                    printk(KERN_INFO "rule %d not match: src ip mismatchn", i);
                    continue;
                }
            }
            if (a_rule->dest_ip == 0) {
                //
            } else {
                if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
                    printk(KERN_INFO "rule %d not match: dest ip mismatchn", i);                  
                    continue;
                }
            }
            //check the port number
            if (a_rule->src_port==0) {
                //rule doesn't specify src port: match
            } else if (src_port!=a_rule->src_port) {
                printk(KERN_INFO "rule %d not match: src port mismatchn", i);
                continue;
            }
            if (a_rule->dest_port == 0) {
                //rule doens't specify dest port: match
            }
            else if (dest_port!=a_rule->dest_port) {
                printk(KERN_INFO "rule %d not match: dest port mismatchn", i);
                continue;
            }
            //a match is found: take action
            if (a_rule->action==0) {
                printk(KERN_INFO "a match is found: %d, drop the packetn", i);
                printk(KERN_INFO "---------------------------------------n");
                return NF_DROP;
            } else {
                printk(KERN_INFO "a match is found: %d, accept the packetn", i);
                printk(KERN_INFO "---------------------------------------n");
                return NF_ACCEPT;
            }
        }
    }
    printk(KERN_INFO "no matching is found, accept the packetn");
    printk(KERN_INFO "---------------------------------------n");
    return NF_ACCEPT;                
}
/*
void add_a_rule(struct mf_rule_desp* a_rule_desp) {
    struct mf_rule* a_rule;
    a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    if (a_rule == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rulen");
        return;
    }
    a_rule->in_out = a_rule_desp->in_out;
    a_rule->src_ip = ip_str_to_hl(a_rule_desp->src_ip);
    a_rule->src_netmask = ip_str_to_hl(a_rule_desp->src_netmask);
    a_rule->src_port = port_str_to_int(a_rule_desp->src_port);
    a_rule->dest_ip = ip_str_to_hl(a_rule_desp->dest_ip);
    a_rule->dest_netmask = ip_str_to_hl(a_rule_desp->dest_netmask);
    a_rule->dest_port = port_str_to_int(a_rule_desp->dest_port);
    a_rule->proto = a_rule_desp->proto;
    a_rule->action = a_rule_desp->action;
    printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, src_port=%u, dest_ip=%u, dest_netmask=%u, dest_port=%u, proto=%u, action=%un", a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);
    INIT_LIST_HEAD(&(a_rule->list));
    list_add_tail(&(a_rule->list), &(policy_list.list));
}
*/
/*
void add_a_test_rule(void) {
    struct mf_rule_desp a_test_rule;
    printk(KERN_INFO "add_a_test_rulen");
    a_test_rule.in_out = 2;
    //a_test_rule.src_ip = (char *)kmalloc(6, GFP_KERNEL);
    //a_test_rule.src_ip = "137.132.165.27";
    //a_test_rule.src_ip = NULL;
    a_test_rule.src_ip = (char *)kmalloc(16, GFP_KERNEL);
    strcpy(a_test_rule.src_ip, "10.0.2.15");   //change 10.0.2.15 to your own IP
    //a_test_rule.src_netmask = NULL;
    a_test_rule.src_netmask = (char *)kmalloc(16, GFP_KERNEL);
    strcpy(a_test_rule.src_netmask, "255.255.255.255");
    a_test_rule.src_port = NULL;
    //a_test_rule.dest_ip = (char *)kmalloc(16, GFP_KERNEL);
    //strcpy(a_test_rule.dest_ip, "137.132.165.25");
    a_test_rule.dest_ip = NULL;
    //a_test_rule.dest_netmask = (char *)kmalloc(16, GFP_KERNEL);
    //strcpy(a_test_rule.dest_netmask, "255.255.255.0");
    a_test_rule.dest_netmask = NULL;
    //a_test_rule.dest_port = "9000";
    a_test_rule.dest_port = NULL;
    a_test_rule.proto = 6;
    a_test_rule.action = 0;
    add_a_rule(&a_test_rule);
}
*/
/*
void delete_a_rule(int num) {
    int i = 0;
    struct list_head *p, *q;
    struct mf_rule *a_rule;
    printk(KERN_INFO "delete a rule: %dn", num);
    list_for_each_safe(p, q, &policy_list.list) {
        ++i;
        if (i == num) {
            a_rule = list_entry(p, struct mf_rule, list);
            list_del(p);
            kfree(a_rule);
            return;
        }
    }
}
*/
/* Initialization routine */

int init_module() {
    printk(KERN_INFO "initialize kernel module: sweepthenet");
    INIT_LIST_HEAD(&(policy_list.list));
    /* Fill in the hook structure for incoming packet hook*/
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);         // Register the hook
    /* Fill in the hook structure for outgoing packet hook*/
    //nfho_out.hook = hook_func_out;
    //nfho_out.hooknum = NF_INET_LOCAL_OUT;
    //nfho_out.pf = PF_INET;
    //nfho_out.priority = NF_IP_PRI_FIRST;
    //nf_register_hook(&nfho_out);    // Register the hook
    /*this part of code is for testing purpose*/
    //add_a_test_rule();
    return 0;
}

/* Cleanup routine */

void cleanup_module() {
    struct list_head *p, *q;
    struct mf_rule *a_rule;
    nf_unregister_hook(&nfho);
    //nf_unregister_hook(&nfho_out);
    printk(KERN_INFO "free policy listn");
    list_for_each_safe(p, q, &policy_list.list) {
        printk(KERN_INFO "free onen");
        a_rule = list_entry(p, struct mf_rule, list);
        list_del(p);
        kfree(a_rule);
    }
    printk(KERN_INFO "kernel module unloaded: sweepthenet");
}
