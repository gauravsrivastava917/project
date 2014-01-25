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

#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Embedded-Linux-Kernel-FireWall");
#define AUTHORS "Anubhav Saini<IAmAnubhavSaini@GMail.com>, " \
                "Anurag Tripathi<700Anurag@GMail.com, "      \
                "Bhanu Soni<I forgot...(>"
MODULE_AUTHOR(AUTHORS);

/* pfs_entry - procfs embedded firewall entry : it
 * has to be global and static for obvious reasons.
 * it's name will be efw and accessible as /proc/efw
 */
static struct proc_dir_entry *pfs_entry; 

#define EFW_PROC_FILE_COUNT 5
/* pfs_rule_files [N] where N:
 * ***************************
 * N = 0 : read only rules file
 * N = 1 : write only rules file
 * N = 2 : log all file
 * N = 3 : match log file
 * N = 4 : non_match log file
 */
static struct proc_dir_entry *pfs_rule_files[EFW_PROC_FILE_COUNT];

/* pfs_wrt_spn_lck - write spin lock for pfs_rwe[1] */
DEFINE_SPINLOCK(pfs_wrt_spn_lck);

static char *FileNames[] = {
  "read", "write", "log_all", "match", "non_match"
};

enum Protocols{
  PRT_INVALID  = -1,
  PRT_ALL      = 1,
  PRT_TCP      = 6,
  PRT_UDP      = 17,
};
enum InOut{
  IO_NEITHER   = 0,
  IO_IN        = 1,
  IO_OUT       = 2,
};
enum Action{
  ACT_BLOCK      = 0,
  ACT_UNBLOCK    = 1,
};
/* I know that I could have left 0,1 .. out in InOut and Action, these
 * are explicit so that the rules stay visible
 */


/*structure for firewall policies*/ 
struct efw_rule_policy {
  unsigned char in_out;
  char *src_ip;
  char *src_netmask;
  char *src_port;
  char *dst_ip;
  char *dst_netmask;
  char *dst_port;
  unsigned char protocol;
  unsigned char action;
};

 

/*structure for firewall policies*/
struct efw_rule {
  unsigned char in_out;        //0: neither in nor out, 1: in, 2: out
  unsigned int src_ip;        //
  unsigned int src_netmask;        //
  unsigned int src_port;        //0~2^32
  unsigned int dst_ip;
  unsigned int dst_netmask;
  unsigned int dst_port;
  unsigned char protocol; /* enum Protocols */       //0: all, 1: tcp, 2: udp
  unsigned char action; /* enum Action */
  struct list_head list;
};

 

static struct efw_rule policy_list;

 
//the structure used to register the function

 
static struct nf_hook_ops nfhops;
static struct nf_hook_ops nfhops_out;

/* seq_file interface */
static void *efw_seq_start(struct seq_file *sfile, loff_t *pos){
/* TODO: */
  return NULL;
}

static void *efw_seq_next(struct seq_file *sfile, void *v, loff_t *pos){
/* TODO: */
  return NULL;
}

static void *efw_seq_stop(struct seq_file *sfile, void *v){
/* TODO: */
  return NULL;
}

static int efw_seq_show(struct seq_file * sfile, void *v){
/* TODO: */
  return 0;
}

static struct seq_operations efw_seq_ops = {
  .start = efw_seq_start,
  .next = efw_seq_next,
  .stop = efw_seq_stop,
  .show = efw_seq_show,
};

static int efw_proc_open(struct inode *inode, struct file *file){
  return seq_open(file, &efw_seq_ops);
}

static struct file_operations efw_proc_ops = {
  .owner = THIS_MODULE,
  .open = efw_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = seq_release,
};

static unsigned int port_str_to_int(char *port_str) {
	unsigned int port = 0;    
	int i = 0;
	if (port_str==NULL) {
		return 0;
	} 

    while (port_str[i]!='\0') {
	port = port*10 + (port_str[i]-'0');
	++i;
	}

    return port;
}

 

static unsigned int ip_str_to_hl(char *ip_str) {

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
    while (ip_str[i]!='\0') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
    return ip;
}

 

/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/

 

static bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
    unsigned int tmp = ntohl(ip);    //network to host long
    int cmp_len = 32;
    int i = 0, j = 0;
    printk(KERN_INFO "compare ip: %u <=> %u\n", tmp, ip_rule);
    if (mask != 0) {
       //printk(KERN_INFO "deal with mask\n");
       //printk(KERN_INFO "mask: %d.%d.%d.%d\n", mask[0], mask[1], mask[2], mask[3]);
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
            printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
            return false;
        }
    }
    return true;
}

//the hook function itself: regsitered for filtering outgoing packets
static unsigned int hook_func_out(unsigned int hooknum, 
                           struct sk_buff *skb, 
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *)) 
{
/* declarations */
   struct iphdr  *ip_header; 
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct list_head *p;
   struct efw_rule *a_rule;
   int i;
   unsigned int src_ip;
   unsigned int dst_ip;
   unsigned int src_port = 0;
   unsigned int dst_port = 0;

/* defintions and assignments */
  ip_header = (struct iphdr *)skb_network_header(skb);
  src_ip = (unsigned int)ip_header->saddr;
  dst_ip = (unsigned int)ip_header->daddr;
  i = src_port = dst_port = 0;

/***get src and dest port number***/
   if (ip_header->protocol == PRT_UDP) {
       udp_header = (struct udphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(udp_header->source);
       dst_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == PRT_TCP) {
       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dst_port = (unsigned int)ntohs(tcp_header->dest);
   }

    printk(KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; protocol: %u\n", src_ip, src_port, dst_ip, dst_port, ip_header->protocol); 

  //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one

 

   list_for_each(p, &policy_list.list) {
       i++;
       a_rule = list_entry(p, struct efw_rule, list);

       printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dst_ip=%u; a_rule->dst_netmask=%u; a_rule->dst_port=%u; a_rule->protocol=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dst_ip, a_rule->dst_netmask, a_rule->dst_port, a_rule->protocol, a_rule->action);

       //if a rule doesn't specify as "out", skip it

       if (a_rule->in_out != 2) {
           printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n", i, a_rule->in_out);
           continue;
       } else {
           //check the protoco
            if ((a_rule->protocol==1) && (ip_header->protocol != 6)) {
              printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);

               continue;
           } else if ((a_rule->protocol==2) && (ip_header->protocol != 17)) {
               printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
                continue;

           }

 

           //check the ip address
           if (a_rule->src_ip==0) {
              //rule doesn't specify ip: match
           } else {
              if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
		 printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }

           }

           if (a_rule->dst_ip == 0) {
               //rule doesn't specify ip: match
           } else {
               if (!check_ip(dst_ip, a_rule->dst_ip, a_rule->dst_netmask)) {
                   printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
                   continue;
               }
           }
           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
               continue;

           }
           if (a_rule->dst_port == 0) {
               //rule doens't specify dest port: match

           }

           else if (dst_port!=a_rule->dst_port) {
               printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;

           }
           //a match is found: take action
           if (a_rule->action==0) {
               printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
              printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {
               printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
              printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }

       }

   }
   printk(KERN_INFO "no matching is found, accept the packet\n");
   printk(KERN_INFO "---------------------------------------\n");
   return NF_ACCEPT;            
}


 
//the hook function itself: registered for filtering incoming packets

static unsigned int hook_func_in(unsigned int hooknum, 
                           struct sk_buff *skb, 
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *)) {
   /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
   struct list_head *p;
   struct efw_rule *a_rule;
   int i = 0;
   /**get src and dest ip addresses**/
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dst_ip = (unsigned int)ip_header->daddr;
   unsigned int src_port = 0;
   unsigned int dst_port = 0;
   /***get src and dest port number***/
   if (ip_header->protocol == PRT_UDP) {
       udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(udp_header->source);
       dst_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == PRT_TCP) {
       tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dst_port = (unsigned int)ntohs(tcp_header->dest);
   }

 

   printk(KERN_INFO "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; protocol: %u\n", src_ip, src_port, dst_ip, dst_port, ip_header->protocol); 

 

   //go through the firewall list and check if there is a match

 

   //in case there are multiple matches, take the first one

 

   list_for_each(p, &policy_list.list) {
		i++;
       a_rule = list_entry(p, struct efw_rule, list);

printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dst_ip=%u; a_rule->dst_netmask=%u; a_rule->dst_port=%u; a_rule->protocol=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dst_ip, a_rule->dst_netmask, a_rule->dst_port, a_rule->protocol, a_rule->action);

 

       //if a rule doesn't specify as "in", skip it
       if (a_rule->in_out != IO_IN) {
           printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n", i, a_rule->in_out);

           continue;
       } else {

           //check the protocol
           if ((a_rule->protocol == PRT_TCP) && (ip_header->protocol != PRT_TCP)){
             printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
             continue;
            } else if ((a_rule->protocol == PRT_UDP) && (ip_header->protocol != PRT_UDP)) {
             printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
             continue;
           }
 

           //check the ip address
           if (a_rule->src_ip == 0) {
 /* future? if ever */
           } else {
              if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
                  printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }

           }
           if (a_rule->dst_ip == 0) {
 /* future? if ever */
          } else {

               if (!check_ip(dst_ip, a_rule->dst_ip, a_rule->dst_netmask)){ 
                   printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);                                  
		 continue;
               }
           }

           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
               continue;
           }
           if (a_rule->dst_port == 0) {
               //rule doens't specify dest port: match
           }
           else if (dst_port!=a_rule->dst_port) {
               printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;
           }
           //a match is found: take action
           if (a_rule->action==0) {
               printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
               printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {

               printk(KERN_INFO "a match is found: %d, accept the packet\n", i);

               printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }

        }
  }

    printk(KERN_INFO "no matching is found, accept the packet\n");

    printk(KERN_INFO "---------------------------------------\n");
    return NF_ACCEPT;                
}

 

static void add_a_rule(struct efw_rule_policy* a_rule_desp) {
    struct efw_rule* a_rule;
    a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    if (a_rule == NULL) {
        printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return;
    }
    a_rule->in_out = a_rule_desp->in_out;
    a_rule->src_ip = ip_str_to_hl(a_rule_desp->src_ip);
    a_rule->src_netmask = ip_str_to_hl(a_rule_desp->src_netmask);
    a_rule->src_port = port_str_to_int(a_rule_desp->src_port);
    a_rule->dst_ip = ip_str_to_hl(a_rule_desp->dst_ip);
    a_rule->dst_netmask = ip_str_to_hl(a_rule_desp->dst_netmask);
    a_rule->dst_port = port_str_to_int(a_rule_desp->dst_port);
    a_rule->protocol = a_rule_desp->protocol;
    a_rule->action = a_rule_desp->action;
    printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, \
	src_port=%u, dst_ip=%u, dst_netmask=%u, dst_port=%u, protocol=%u, \
	action=%u\n", a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, 
	 a_rule->src_port, a_rule->dst_ip, a_rule->dst_netmask,
	 a_rule->dst_port, a_rule->protocol, a_rule->action);
    
   INIT_LIST_HEAD(&(a_rule->list));
   list_add_tail(&(a_rule->list), &(policy_list.list));

}

 

static void add_a_test_rule(void) {
    struct efw_rule_policy a_test_rule;
    printk(KERN_INFO "add_a_test_rule\n");
    a_test_rule.in_out = IO_OUT;
    a_test_rule.src_ip = (char *)kmalloc(16, GFP_KERNEL);
    strcpy(a_test_rule.src_ip, "127.0.0.1");   //change 10.0.2.15 to your own IP
    a_test_rule.src_netmask = (char *)kmalloc(16, GFP_KERNEL);
    strcpy(a_test_rule.src_netmask, "0.0.0.0");
    a_test_rule.src_port = NULL;
    a_test_rule.dst_ip = NULL;
    a_test_rule.dst_netmask = NULL;
    a_test_rule.dst_port = NULL;
    a_test_rule.protocol = PRT_TCP;
    a_test_rule.action = ACT_BLOCK;
    add_a_rule(&a_test_rule);

}

 

 
static void delete_a_rule(int num) {
    int i = 0;
    struct list_head *p, *q;
    struct efw_rule *a_rule;
    printk(KERN_INFO "delete a rule: %d\n", num);
    list_for_each_safe(p, q, &policy_list.list) {
        ++i;
        if (i == num) {
            a_rule = list_entry(p, struct efw_rule, list);
            list_del(p);
            kfree(a_rule);
            return;
        }
    }
}
static int EFW_FILES_INITED[EFW_PROC_FILE_COUNT];

/* Initialization routine */
int __init sf_init_module(void) {
  int i;
  struct proc_dir_entry *tmpde;
    printk(KERN_INFO "initialize kernel module\n");
    INIT_LIST_HEAD(&(policy_list.list));
    /* Fill in the hook structure for incoming packet hook*/
    nfhops.hook = hook_func_in;
    nfhops.hooknum = NF_INET_LOCAL_IN;
    nfhops.pf = PF_INET;
    nfhops.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfhops);         // Register the hook
    /* Fill in the hook structure for outgoing packet hook*/
    nfhops_out.hook = hook_func_out;
    nfhops_out.hooknum = NF_INET_LOCAL_OUT;
    nfhops_out.pf = PF_INET;
    nfhops_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfhops_out);    // Register the hook

  pfs_entry = proc_mkdir("efw", NULL);
  if(pfs_entry){
    for(i = 0; i < EFW_PROC_FILE_COUNT; i += 1){
      tmpde = proc_create(FileNames[i], 0 /* what is mode? */, pfs_entry, &efw_proc_ops);
      if(tmpde){
 
        /* TODO: error and other things */
  
        /* then update the global array */
        pfs_rule_files[i] = tmpde;
        EFW_FILES_INITED[i] = 1;
      } else {
/* this is delibrate; for visibility */
        EFW_FILES_INITED[i] = 0;
      }
    }
  } else { //if pfs_entry i.e. /proc/efw was not created
  }
  /*this part of code is for testing purpose*/

    add_a_test_rule();
    return 0;
}

/* Cleanup routine */

void __exit sf_cleanup_module(void) {
  int i = 0;
    struct list_head *p, *q;
    struct efw_rule *a_rule;
    nf_unregister_hook(&nfhops);
    nf_unregister_hook(&nfhops_out);
    printk(KERN_INFO "free policy list\n");
    list_for_each_safe(p, q, &policy_list.list) {
        printk(KERN_INFO "free one\n");
        a_rule = list_entry(p, struct efw_rule, list);
        list_del(p);
        kfree(a_rule);
    }
  for(i = 0; i < EFW_PROC_FILE_COUNT; i += 1){
    if(EFW_FILES_INITED[i]){
      //proc_remove(pfs_rule_files[i]);
      remove_proc_entry(pfs_rule_files[i]->name, pfs_entry);
    }
  }
 // proc_remove(pfs_entry);
  remove_proc_entry(pfs_entry->name, NULL);
	printk(KERN_INFO "kernel module unloaded.\n");
}

module_init(sf_init_module);
module_exit(sf_cleanup_module);
