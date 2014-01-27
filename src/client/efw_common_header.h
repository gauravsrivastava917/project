/* efw_common_header.h 
 *
 * common for client and module
 */

#ifndef EFW_COMMON_HEADER_H
#define EFW_COMMON_HEADER_H

#define EFW_PROC_DIR_ENTRY "efw"
#define EFW_FILE_PATH_PREFIX "/proc/"EFW_PROC_DIR_ENTRY"/"

#define EFW_PROC_FILE_COUNT 5
/* pfs_rule_files [N] where N:
 * ***************************
 * N = 0 : read only rules file
 * N = 1 : write only rules file
 * N = 2 : log all file
 * N = 3 : match log file
 * N = 4 : non_match log file
 */
/* this is place where, we would have loved to have either one of the following
 * static struct proc_dir_entry *pfs_rule_files[EFW_PROC_FILE_COUNT];
 * OR
 * static int *efw_files_fd[EFW_PROC_FILE_COUNT];
 */

/* file names in the proc/efw */
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
  ACT_ACCEPT     = 1,
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

#endif //EFW_COMMON_HEADER_H
