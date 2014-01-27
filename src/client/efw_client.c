#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> /* for perror */
#include <errno.h>
#include "efw_common_header.h"
#include "efw_client_header.h"

/* open_files() opens and sets file descriptors of the files 
 * that we need for our operation
 */
int open_files(){
  int i;
  char *tmp_filename;

  tmp_filename = calloc(EFW_PROC_FILE_COUNT, EFW_MAX_FILE_PATH_LEN);
  if(!tmp_filename){
    write(STDERR_FILENO, ERR_ALLOCATING_MEM, strlen(ERR_ALLOCATING_MEM));
    return -1;
  }

  for(i = 0; i < EFW_PROC_FILE_COUNT; i++){
    strncpy(tmp_filename, EFW_FILE_PATH_PREFIX, strlen(EFW_FILE_PATH_PREFIX));
    strcat(tmp_filename, FileNames[i]);
    
    efw_files_fd[i] = open(tmp_filename, flag_values[i]);
    if(efw_files_fd[i] == -1){
      write(STDERR_FILENO, ERR_FILE_OPENING, strlen(ERR_FILE_OPENING));
      /* we do not need to break program here.
       * we can base our further execution on the fact that
       * accessible files have their fd not equal to -1. So that.
       */
    }
    memset(tmp_filename, 0, EFW_MAX_FILE_PATH_LEN);
  }
  free(tmp_filename);

  return 1; /* FIXME */
}


/* display_menu() displays menu that user can use to access information 
 * and take action based on the information
 */
int display_menu(){
/* TODO: menu being called twice for one entry. FIXME */

  /* what user enters when it sees the menu */
  static int user_choice;
  int i = 0;
  /* since I need only one character: '1', '2', '3', '4', ... */
  char user_input;
  static const char *enter_choice_msg = "Please enter a choice: \n";
  static const char *choices[] = {
    "1. read rules\n",
    "2. add rules\n",
    "3. read log\n",
    "4. read match log\n",
    "5. read non match log\n",
    "------------------------\n",
    "6. save rules\n",
    "7. delete rules\n",
    "0. exit\n",
    "------------------------> ",
    NULL
  };

  do{
    if(user_input != '\n'){
      write(STDOUT_FILENO, enter_choice_msg, strlen(enter_choice_msg));
      for(i = 0; choices[i] != NULL; i++){
        write(STDOUT_FILENO, choices[i], strlen(choices[i]));
      }
    }
    if(sizeof(char) == read(STDIN_FILENO, (void*)&user_input, sizeof(char))){
      /* if we are here, it means we got the value */
// CHECKED:     write(STDOUT_FILENO, &user_input, sizeof(char));
      switch(user_input){
      case '1': case 'r': read_rules(); break;
      case '2': case 'a': add_rules();  break;
      case '3': case 'l': read_log(user_input); break;
      case '4': read_log(user_input); break;
      case '5': read_log(user_input); break;
      case '6': case 's': save_rules(); break;
      case '7': case 'd': delete_rules(); break;
      case '0': case 'q': case 'e': goto done_with_menu;
      case '\n': 
        /* write(STDOUT_FILENO, choices[9], strlen(choices[9])); */
        break;
      default:
        write(STDERR_FILENO, WARN_WRONG_CHOICE, strlen(WARN_WRONG_CHOICE));
        break;
      }
    }
    
  } while(user_input != '0');

done_with_menu:
  return 1; /* FIXME */
}

int read_rules(){ 
#define RDLEN 16
  size_t len;
  ssize_t ret;
  char *buf, *tmp;
  int total;
  total = 0;
  buf = calloc(RDLEN, sizeof(char));
  tmp = buf;
  if(efw_files_fd[0] == -1){
    perror(ERR_FILE_OPENING);
    perror(ERR_FILE_READING);
    return -1;
  }
  
  do{
    len = RDLEN;
    while(len != 0 && (ret = read(efw_files_fd[0], buf, RDLEN))){
      if(ret == -1){
        if(errno == EINTR)
          continue;
        perror("ERROR: in read_rules: cannot read file. Sorry.\n");
        break;
      }
      len -= ret;
      buf += ret;
      total += ret;
    }
    write(STDOUT_FILENO, buf, RDLEN);
    memset(buf, '0', RDLEN);
  } while(ret != 0);

  return 0; /* FIXME */
}
  
int add_rules() { return 0; }
int read_log(char which){ return 0; }
int save_rules(){ return 0; }
int delete_rules(){ return 0; }

int main(int argc, char *args[])
{  
  open_files();

  display_menu();

  return 0; /* FIXME */
}


