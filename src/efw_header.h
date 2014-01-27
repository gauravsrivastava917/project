
#ifndef EFW_HEADER_H
#define EFW_HEADER_H

#include "efw_common_header.h"

static struct proc_dir_entry *pfs_rule_files[EFW_PROC_FILE_COUNT];

/* actual structure that will be in the list */
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

/* structure to convey information to user and receive from user */
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

/* for __init and __exit
 * this array of initialized files helps in knowing 
 * which files have been initialized and which have not been
 */
static int EFW_FILES_INITED[EFW_PROC_FILE_COUNT];


#endif // EFW_HEADER_H
