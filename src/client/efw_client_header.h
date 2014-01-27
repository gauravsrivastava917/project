/* efw_client_header.h
 *
 * contains information that is important for client only
 */

#ifndef EFW_CLIENT_HEADER_H
#define EFW_CLIENT_HEADER_H

#include "efw_common_header.h"

static int efw_files_fd[EFW_PROC_FILE_COUNT];
static int efw_files_flags[EFW_PROC_FILE_COUNT];

static int flag_values[] = {
  O_RDONLY, O_WRONLY, O_RDONLY, O_RDONLY, O_RDONLY
};

#define EFW_MAX_FILE_PATH_LEN 30

#define ERR_ALLOCATING_MEM "ERROR: Cannot allocate memory. Sorry.\n"
#define ERR_FILE_OPENING "ERROR: Cannot open file. Check path. Sorry.\n"
#define ERR_FILE_READING "ERROR: Cannot read from file. Check path. Sorry.\n"
#define WARN_WRONG_CHOICE "WARNING: Wrong choice my friend. Try again!\n"

/* functions
 */
int open_files();
int display_menu();
int read_rules();
int add_rules();
int read_log(char which);
int save_rules();
int delete_rules();

#endif //EFW_CLIENT_HEADER_H
