/* things that are present here 
 * enum Protocols
 * enum InOut
 * enum Action
 * static char *FileNames[];
 * static struct proc_dir_entry *pfs_rule_files[EFW_PROC_FILE_COUNT];
 * static struct proc_dir_entry *pfs_entry; 
 * struct efw_rule_char;
 * struct efw_rule;
 * static struct efw_rule policy_list;
 * static struct nf_hook_ops nfhops;
 * static struct nf_hook_ops nfhops_out;
 * static void *efw_seq_start(struct seq_file *sfile, loff_t *pos);
 * static void *efw_seq_next(struct seq_file *sfile, void *v, loff_t *pos);
 * static void *efw_seq_stop(struct seq_file *sfile, void *v);
 * static int efw_seq_show(struct seq_file * sfile, void *v);
 * static struct seq_operations efw_seq_ops;
 * static int efw_proc_open(struct inode *inode, struct file *file);
 * static struct file_operations efw_proc_ops;
 * static void port_int_to_str(unsigned int port, char *port_str);
 * static unsigned int port_str_to_int(char *port_str);
 * static unsigned int ip_str_to_hl(char *ip_str);
 * static void ip_hl_to_str(unsigned int ip, char *ip_str)
 * static bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask);
 * static unsigned int hook_func_out(unsigned int hooknum, 
                           struct sk_buff *skb, 
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *));
 * static unsigned int hook_func_in(unsigned int hooknum, 
                           struct sk_buff *skb, 
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *));
 * static void add_a_rule(struct efw_rule_char* a_rule_char);
 * static void add_a_test_rule(void);
 * static void delete_a_rule(int num);
 * static int EFW_FILES_INITED[EFW_PROC_FILE_COUNT];
 * int __init sf_init_module(void);
 * void __exit sf_cleanup_module(void);
 * module_init(sf_init_module);
 * module_exit(sf_cleanup_module);
 * 
 * 
 * 
 */



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
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Embedded-Linux-Kernel-FireWall");
#define AUTHORS "Anubhav Saini<IAmAnubhavSaini@GMail.com>, " \
                "Anurag Tripathi<700Anurag@GMail.com, "      \
                "Bhanu Soni<I forgot...(>"
MODULE_AUTHOR(AUTHORS);

/* load time configuration variables */
static int log_length = 64;
module_param(log_length, int, S_IRUGO);
/* log count is the thing that will keep track of the log messages in the doubly-linked list
 * we will be using dl-list as a queue after log_count >= log_length 
 * */
static int log_count = 0; 

/* log_mode will tell what things to log.
 * MINIMAL: only log on exit from hooks once.
 * MATCH : log when packet mathes rule + MINIMAL.
 * UNMATCH : log when packet doesn't match any rule + MINIMAL.
 * ALL : just log every packet ever where.
 */
static int log_mode = 0; /* MINIMAL logging */
module_param(log_mode, int, S_IRUGO);



/* pfs_entry - procfs embedded firewall entry : it
 * has to be global and static for obvious reasons.
 * it's name will be efw and accessible as /proc/efw
 */
static struct proc_dir_entry *pfs_entry; 

#define RULE_LENGTH 80

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
enum Actions{
  ACT_BLOCK      = 0,
  ACT_UNBLOCK    = 1,
};
/* I know that I could have left 0,1 .. out in InOut and Action, these
 * are explicit so that the rules stay visible
 */
enum LogMode{
  LM_MINIMAL,
  LM_MATCH,
  LM_UNMATCH,
  LM_ALL
};
/* structure for logging packets */
static int log_pkt_count = 0 __initconst;
struct pkt_log_msgs{
  char *msg;
  struct list_head list;
};
#define get_pkt_log_msg(name) container_of(name, struct pkt_log_msgs, list)

static struct log_msgs *pkt_log;



/*structure for firewall policies*/ 
struct efw_rule_char {
  char *in_out;
  char *src_ip;
  char *src_netmask;
  char *src_port;
  char *dst_ip;
  char *dst_netmask;
  char *dst_port;
  char *protocol;
  char *action;
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
  int protocol; /* enum Protocols */       //0: all, 1: tcp, 2: udp
  int action; /* enum Action */
  struct list_head list;
};

#define get_rule(name) container_of(name, struct efw_rule, list) 

static struct efw_rule policy_list;


static int log_packet(struct efw_rule_char *rules){
  int len;
  char *message;
  struct log_msgs *log;
  len = strlen(rules->dst_ip) + strlen(rules->dst_netmask) + strlen(rules->dst_port)
      + strlen(rules->src_ip) + strlen(rules->src_netmask) + strlen(rules->port)
      + strlen(rules->action) + strlen(rules->in_out) + strlen(rules->protocol)
      + strlen("log  #1234567890: -> | ACT") + 30 ;
      
      
  message = kzalloc(sizeof(char)*len, GFP_KERNEL);
  if(message == NULL){
    printk(KERN_ERR "func-log_packet: cannot assign memory! for message.\n");
    return -ENOMEM;
  }
  log = kzalloc(sizeof(struct log_msgs), GFP_KERNEL);
  if(log == NULL){
    printk(KERN_ERR "func-log_packet: cannot assign memory! for log.\n");
    return -ENOMEM;
  }
  
  
  sprintf(message, "log #%d - %s:%s/%s -> %s:%s/%s | %s | ACT = %s\n", 
                   log_pkt_count, rules->src_ip, rules->src_port, rules->src_netmask,
                                  rules->dst_ip, rules->dst_port, rules->dst_netmask,
                   rules->in_out, rules->action 
         );
  
  log -> msg = message;
  list_add_tail(&(log->list), &(pkt_log->list));
  
  return 0;
}
 

static void port_int_to_str(unsigned int port, char *port_str) {
  sprintf(port_str, "%u", port);
}

static unsigned int port_str_to_int(char *port_str) {
	unsigned int port = 0;    
	int i = 0;
	if (port_str==NULL) {
		return 0;
	} 

    while (port_str[i]!='\0') {
	port = port*10 + (port_str[i]-'0');
	i += 1;
	}

    return port;
}

static void protocol_int_to_str(unsigned int protocol, char *str) {
  sprintf(str, "%u", protocol);
}

static unsigned int protocol_str_to_int(char *str) {
  unsigned int protocol = 0;    
  int i = 0;
  if (str==NULL) {
    return 0;
  } 
  while(str[i] != '\0') {
    protocol = protocol*10 + (str[i] - '0');
    i += 1;
  }
  return protocol;
}

static void ip_hl_to_str(unsigned int ip, char *ip_str) {
    /*convert hl to byte array first*/
  unsigned char ip_array[4];
  memset(ip_array, 0, 4);
  ip_array[0] = (ip_array[0] | (ip >> 24));
  ip_array[1] = (ip_array[1] | (ip >> 16));
  ip_array[2] = (ip_array[2] | (ip >> 8));
  ip_array[3] = (ip_array[3] | ip);
  sprintf(ip_str, "%u.%u.%u.%u", 
                  ip_array[0], ip_array[1], 
                  ip_array[2], ip_array[3]);

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
    ip_array[0] = ip_array[0]*10 + (ip_str[i += 1]-'0');
  }
  i += 1;
  while (ip_str[i]!='.') {
    ip_array[1] = ip_array[1]*10 + (ip_str[i += 1]-'0');
  }
  i += 1;
  while (ip_str[i]!='.') {
    ip_array[2] = ip_array[2]*10 + (ip_str[i += 1]-'0');
  }
  i += 1;
  while (ip_str[i]!='\0') {
    ip_array[3] = ip_array[3]*10 + (ip_str[i += 1]-'0');
  }
  /*convert from byte array to host long integer format*/
  ip = (ip_array[0] << 24);
  ip = (ip | (ip_array[1] << 16));
  ip = (ip | (ip_array[2] << 8));
  ip = (ip | ip_array[3]);
  //printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
  return ip;
}

 

/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/

 

static bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
    unsigned int tmp = ntohl(ip);    //network to host long
    int cmp_len = 32;
    int i = 0, j = 0;
    //printk(KERN_INFO "compare ip: %u <=> %u\n", tmp, ip_rule);
    if (mask != 0) {
       ////printk(KERN_INFO "deal with mask\n");
       ////printk(KERN_INFO "mask: %d.%d.%d.%d\n", mask[0], mask[1], mask[2], mask[3]);
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
            //printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
            return false;
        }
    }
    return true;
}


static char * efw_rule_to_str(const struct efw_rule * rule){
  char *rule_str = kmalloc(81, GFP_KERNEL);
  char *tmp = kmalloc(20, GFP_KERNEL);
  if(rule_str == NULL){
    //printk(KERN_ERR "Cannot allocate memory %d", RULE_LENGTH+1); 
    return NULL;
  }
  /* source */
  sprintf(tmp, "src:-) ");
  strcat(rule_str, tmp);

printk(KERN_INFO "%s", rule_str);

  ip_hl_to_str(rule -> src_ip, tmp);
  strcat(rule_str, tmp);

printk(KERN_INFO "%s", rule_str);

  sprintf(tmp, ":");
  strcat(rule_str, tmp);

printk(KERN_INFO "%s", rule_str);
  port_int_to_str(rule -> src_port, tmp);
  strcat(rule_str, tmp);

printk(KERN_INFO "%s", rule_str);
  sprintf(tmp, "/");
  strcat(rule_str, tmp);

//printk(KERN_INFO "%s", rule_str);
  //TODO: netmask_int_to_str(rule -> netmask, rule_str);
  sprintf(tmp, " | dst:-) ");
  strcat(rule_str, tmp);

  ip_hl_to_str(rule -> dst_ip, tmp);
  strcat(rule_str, tmp);

  sprintf(tmp, ":");
  strcat(rule_str, tmp);

  port_int_to_str(rule -> dst_port, tmp);
  strcat(rule_str, tmp);

  sprintf(tmp, "/");
  strcat(rule_str, tmp);

  //TODO: netmask_int_to_str(rule -> netmask, rule_str);
  sprintf(tmp, " | ACT:-) ");
  strcat(rule_str, tmp);

  //TODO: action_int_to_str(rule -> action, rule_str);
  strcat(rule_str, "\n\0");
  return rule_str;
}

//the structure used to register the function
static struct nf_hook_ops nfhops;
static struct nf_hook_ops nfhops_out;

/* seq_file interface */
static void *efw_seq_start(struct seq_file *sfile, loff_t *pos){
/* TODO: have we completed it? */
  struct efw_rule * rule;
  loff_t off = 0;
  list_for_each_entry(rule, &(policy_list.list), list){
    if(off++ == *pos){
      return rule;
    }
  }
  return NULL;
}
/* for log_all file */
static void *efw_seq_log_start(struct seq_file *sfile, loff_t *pos){
  struct log_msgs *msg;
  loff_t off = 0;
  list_for_each_entry(msg, &(pkt_log.list), list){
    if(off++ == *pos){
      return msg;
    }
  }
  return NULL;
}
/* for write file */
static void *efw_seq_write_start(struct seq_file *sfile, loff_t *pos){
  seq_printf(sfile, "This is a write only file; meant to write in the firewall rules.\n");
  return NULL;
}
static void *efw_seq_next(struct seq_file *sfile, void *v, loff_t *pos){
/* TODO: */
  struct list_head *trule = ((struct efw_rule *)v) -> list.next;
  (*pos) += 1; /* could have been ++*pos also */
  
  return (trule != &(policy_list.list))
      ? 
        list_entry(trule, struct efw_rule, list)
      : 
        NULL;
}
/* for log_all file */
static void *efw_seq_log_next(struct seq_file *sfile, void *v, loff_t *pos){
  struct list_head *msghead = ((struct pkt_log_msgs *)v) -> list.next;
  (*pos) += 1;
  return (msghead != &(pkt_log->lis))
    ?    list_entry(msghead, struct pkt_log_msgs, list)
    :    NULL;
}
static void *efw_seq_stop(struct seq_file *sfile, void *v){
/* TODO: */
  return NULL;
}

static int efw_seq_show(struct seq_file *sfile, void *v){
/* TODO: */
  int ret;
  const struct efw_rule *trule = v;
  char *rule_str = efw_rule_to_str(trule);
  ret = seq_printf(sfile, rule_str);
  //printk(KERN_INFO "wrote %s to seq file in efw_seq_show.\n", rule_str);
  kfree(rule_str); 
  return ret;
}
/* for log_all file */
static int efw_seq_log_show(struct seq_file *sfile, void *v)
{
  int ret;
  const struct pkt_log_msgs *msg = v;
  ret = seq_printf(sfile, msg->msg);
  return ret;
}

static struct seq_operations efw_seq_ops = {
  .start = efw_seq_start,
  .next = efw_seq_next,
  .stop = efw_seq_stop,
  .show = efw_seq_show,
};
static struct seq_operations efw_seq_log_ops = {
  .start = efw_seq_log_start,
  .next = efw_seq_log_next,
  .stop = efw_seq_stop,
  .show = efw_seq_log_show,
};
static struct seq_operations efw_seq_write_ops = {
  .start = efw_seq_write_start,
  .next = efw_seq_next,
  .stop = efw_seq_stop,
  .show = efw_seq_show,
};
static int efw_proc_open(struct inode *inode, struct file *file){
  return seq_open(file, &efw_seq_ops);
}
static int efw_proc_log_open(struct inode *inode, struct file *file){
  return seq_open(file, &efw_seq_log_ops);
}
static int efw_proc_write_open(struct inode *inode, struct file *file){
  return seq_open(file, &efw_seq_write_ops);
}

static struct file_operations efw_proc_ops = {
  .owner = THIS_MODULE,
  .open = efw_proc_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = seq_release,
};
static struct file_operations efw_proc_log_ops = {
  .owner = THIS_MODULE,
  .open = efw_proc_log_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = seq_release,
};
static struct file_operations efw_proc_write_ops = {
  .owner = THIS_MODULE,
  .open = efw_proc_write_open,
  .read = seq_read,
  .llseek = seq_lseek,
  .release = seq_release,
};


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
   unsigned int src_port;
   unsigned int dst_port;

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

    //printk(KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; protocol: %u\n", src_ip, src_port, dst_ip, dst_port, ip_header->protocol); 

  //go through the firewall list and check if there is a match
   //in case there are multiple matches, take the first one

   list_for_each(p, &policy_list.list) {
       i += 1;
       a_rule = list_entry(p, struct efw_rule, list);

       //printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dst_ip=%u; a_rule->dst_netmask=%u; a_rule->dst_port=%u; a_rule->protocol=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dst_ip, a_rule->dst_netmask, a_rule->dst_port, a_rule->protocol, a_rule->action);

       //if a rule doesn't specify as "out", skip it

       if (a_rule->in_out != IO_OUT) {
//           //printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n", i, a_rule->in_out);
         continue;
       } else {
           //check the protoco
         if ((a_rule->protocol == PRT_TCP) && (ip_header->protocol != PRT_TCP)) {
//              //printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
           continue;
         } else if ((a_rule->protocol == PRT_UDP) && (ip_header->protocol != PRT_UDP)) {
//               //printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
           continue;

         }
           //check the ip address
         if (a_rule->src_ip == 0) {
              //rule doesn't specify ip: match
         } else {
           if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
// //printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
             continue;
           }
         }

         if (a_rule->dst_ip == 0) {
              //rule doesn't specify ip: match
         } else {
             if (!check_ip(dst_ip, a_rule->dst_ip, a_rule->dst_netmask)) {
//                  //printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
               continue;
             }
         }
           //check the port number
         if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
         } else if (src_port!=a_rule->src_port) {
//               //printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
           continue;

         }
         if (a_rule->dst_port == 0) {
               //rule doens't specify dest port: match

         } else if (dst_port!=a_rule->dst_port) {
//               //printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
           continue;

         }
           //a match is found: take action
         if (a_rule->action==0) {
//               //printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
//              //printk(KERN_INFO "---------------------------------------\n");
           return NF_DROP;
         } else {
//               //printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
//              //printk(KERN_INFO "---------------------------------------\n");
           return NF_ACCEPT;
         }

      }

   }
//   //printk(KERN_INFO "no matching is found, accept the packet\n");
//   //printk(KERN_INFO "---------------------------------------\n");
  return NF_ACCEPT;            
}


 
//the hook function itself: registered for filtering incoming packets

static unsigned int hook_func_in(unsigned int hooknum, 
                           struct sk_buff *skb, 
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff *)) 
{
   /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/  
  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
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
  //printk(KERN_INFO "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; protocol: %u\n", src_ip, src_port, dst_ip, dst_port, ip_header->protocol); 

   //go through the firewall list and check if there is a match

   //in case there are multiple matches, take the first one

  list_for_each(p, &policy_list.list) {
    i += 1;
    a_rule = list_entry(p, struct efw_rule, list);
/*    printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; " \
                     "a_rule->src_netmask=%u; a_rule->src_port=%u; "       \
                     "a_rule->dst_ip=%u; a_rule->dst_netmask=%u; "         \
                     "a_rule->dst_port=%u; a_rule->protocol=%u; "          \
                     "a_rule->action=%u\n",
                      i, a_rule->in_out, a_rule->src_ip, 
                      a_rule->src_netmask, a_rule->src_port, 
                      a_rule->dst_ip, a_rule->dst_netmask, 
                      a_rule->dst_port, a_rule->protocol, 
                      a_rule->action
    ); //printf ends here. bad bad coding by the way!
*/

  //if a rule doesn't specify as "in", skip it
  if (a_rule->in_out != IO_IN) {
    //printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n", i, a_rule->in_out);

           continue;
       } else {

           //check the protocol
           if ((a_rule->protocol == PRT_TCP) && (ip_header->protocol != PRT_TCP)){
             //printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
             continue;
            } else if ((a_rule->protocol == PRT_UDP) && (ip_header->protocol != PRT_UDP)) {
             //printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
             continue;
           }
 

           //check the ip address
           if (a_rule->src_ip == 0) {
 /* future? if ever */
           } else {
              if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
                  //printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
                  continue;
              }

           }
           if (a_rule->dst_ip == 0) {
 /* future? if ever */
          } else {

               if (!check_ip(dst_ip, a_rule->dst_ip, a_rule->dst_netmask)){ 
                   //printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);                                  
		 continue;
               }
           }

           //check the port number
           if (a_rule->src_port==0) {
               //rule doesn't specify src port: match
           } else if (src_port!=a_rule->src_port) {
               //printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
               continue;
           }
           if (a_rule->dst_port == 0) {
               //rule doens't specify dest port: match
           }
           else if (dst_port!=a_rule->dst_port) {
               //printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
               continue;
           }
           //a match is found: take action
           if (a_rule->action==0) {
               //printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
               //printk(KERN_INFO "---------------------------------------\n");
               return NF_DROP;
           } else {

               //printk(KERN_INFO "a match is found: %d, accept the packet\n", i);

               //printk(KERN_INFO "---------------------------------------\n");
               return NF_ACCEPT;
           }

        }
  }

    //printk(KERN_INFO "no matching is found, accept the packet\n");

    //printk(KERN_INFO "---------------------------------------\n");
    return NF_ACCEPT;                
}

 

static void add_a_rule(struct efw_rule_char* a_rule_char) {
    struct efw_rule* a_rule;
    a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);
    if (a_rule == NULL) {
        //printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
        return;
    }
    a_rule->in_out = a_rule_char->in_out;
    a_rule->src_ip = ip_str_to_hl(a_rule_char->src_ip);
    a_rule->src_netmask = ip_str_to_hl(a_rule_char->src_netmask);
    a_rule->src_port = port_str_to_int(a_rule_char->src_port);
    a_rule->dst_ip = ip_str_to_hl(a_rule_char->dst_ip);
    a_rule->dst_netmask = ip_str_to_hl(a_rule_char->dst_netmask);
    a_rule->dst_port = port_str_to_int(a_rule_char->dst_port);
    a_rule->protocol = a_rule_char->protocol;
    a_rule->action = a_rule_char->action;
/*    printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, \
	src_port=%u, dst_ip=%u, dst_netmask=%u, dst_port=%u, protocol=%u, \
	action=%u\n", a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, 
	 a_rule->src_port, a_rule->dst_ip, a_rule->dst_netmask,
	 a_rule->dst_port, a_rule->protocol, a_rule->action);
*/  
   INIT_LIST_HEAD(&(a_rule->list));
   list_add_tail(&(a_rule->list), &(policy_list.list));

}

 

static void add_a_test_rule(void) {
    struct efw_rule_char a_test_rule;
    //printk(KERN_INFO "add_a_test_rule\n");
    a_test_rule.in_out = IO_OUT;
    a_test_rule.src_ip = (char *)kmalloc(16, GFP_KERNEL);
    strcpy(a_test_rule.src_ip, "127.0.0.1");   //change 10.0.2.15 to your own IP
    a_test_rule.src_netmask = (char *)kzalloc(16, GFP_KERNEL);
    strcpy(a_test_rule.src_netmask, "0.0.0.0");
    a_test_rule.src_port = NULL;
    a_test_rule.dst_ip = NULL;
    a_test_rule.dst_netmask = NULL;
    a_test_rule.dst_port = NULL;
    a_test_rule.protocol = PRT_TCP;
    a_test_rule.action = ACT_BLOCK;
    add_a_rule(&a_test_rule);

}

static void init_efw_rule_char(struct efw_rule_char* a_rule_char) {
    a_rule_char->in_out      = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->src_ip      = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->src_netmask = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->src_port    = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->dst_ip      = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->dst_netmask = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->dst_port    = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->protocol    = (char*)kzalloc(16, GFP_KERNEL);
    a_rule_char->action      = (char*)kzalloc(16, GFP_KERNEL);
}
 

 
static void delete_a_rule(int num) {
    int i = 0;
    struct list_head *p, *q;
    struct efw_rule *a_rule;
    //printk(KERN_INFO "delete a rule: %d\n", num);
    list_for_each_safe(p, q, &policy_list.list) {
        i += 1;
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
int __init efw_init_module(void) {
  int i;
  struct proc_dir_entry *tmpde;
    //printk(KERN_INFO "initialize kernel module\n");
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
/* PROC FS code */
  pfs_entry = proc_mkdir("efw", NULL);
  if(pfs_entry){
    for(i = 0; i < EFW_PROC_FILE_COUNT; i += 1){
      if(i == 1){
        tmpde = proc_create(FileNames[i], 0 /* what is mode? */, pfs_entry, &efw_proc_write_ops);
      } else if(i == 2){
        tmpde = proc_create(FileNames[i], 0 /* what is mode? */, pfs_entry, &efw_proc_log_ops);
      } else {
        tmpde = proc_create(FileNames[i], 0 /* what is mode? */, pfs_entry, &efw_proc_ops);
      }
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
/* PROC FS code ends here */

    add_a_test_rule();
    return 0;
}

/* Cleanup routine */

void __exit efw_cleanup_module(void) {
  int i = 0;
    struct list_head *p, *q;
    struct efw_rule *a_rule;
    nf_unregister_hook(&nfhops);
    nf_unregister_hook(&nfhops_out);
    //printk(KERN_INFO "free policy list\n");
    list_for_each_safe(p, q, &policy_list.list) {
        //printk(KERN_INFO "free one\n");
        a_rule = list_entry(p, struct efw_rule, list);
        list_del(p);
        kfree(a_rule);
    }
  for(i = 0; i < EFW_PROC_FILE_COUNT; i += 1){
    if(EFW_FILES_INITED[i]){
      proc_remove(pfs_rule_files[i]);
/* TODO: automaticize it:    proc_remove(pfs_rule_files[i]); */
//      remove_proc_entry(FileNames[i], pfs_entry);
    }
  }
  proc_remove(pfs_entry);
/* TODO: automaticize it:  proc_remove(pfs_entry); */
//  remove_proc_entry(pfs_entry->name, NULL);
  //printk(KERN_INFO "kernel module unloaded.\n");
}

module_init(efw_init_module);
module_exit(efw_cleanup_module);
