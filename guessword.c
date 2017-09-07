#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

//forward declrations
typedef struct Account Account;
void parse_shadow(char*);
void read_shadow_passwd(char*, char*);
void read_dict();
void cleanup();
void parse_accounts(FILE*, FILE*);
/******************************************/

//globals
char* g_salt;
char** g_dict;
int g_dict_len;
Account* g_accounts;
/******************************************/

// consts
/* const char* DICT_PATH = "./dictionary/gutenberg/dict.txt"; */
const char* DICT_PATH = "./out.txt";
const int SALT_DELIMITER = '$';
/******************************************/

struct Account{
  char* fullname;
  char* username;
  char* passwd_hash;
};

void set_salt(char* shadow_entry){
  g_salt = malloc(strlen(shadow_entry));
  strncpy(g_salt, &shadow_entry[7], 6);
  g_salt[6] = '\0';
  /* fprintf(stderr, "salt %s", g_salt); */
}

void read_shadow_passwd(char* shadow_path, char* passwd_path){
  FILE* shadow_file;
  FILE* passwd_file;

  shadow_file = fopen(shadow_path, "r");
  passwd_file = fopen(passwd_path, "r");

  if(shadow_file == NULL || passwd_file == NULL){
    fprintf(stderr, "shadow file or passwd file incorrect path!");
    exit(1);
  }

  char* shadow_line = NULL;
  char* passwd_line = NULL;
  size_t len = 0;
  size_t p_len = 0;
  getline(&shadow_line, &s_len, shadow_file);
  rewind(shadow_file);
  set_salt(shadow_line);

}

void cleanup(){
  for(int i=0; i<g_dict_len;i++){
    free(g_dict[i]);
  }
  free(g_dict);
}

void read_dict(){
  int init_buf_len = 50000; //20,000 lines
  int eof = 0;
  FILE* dict_file;
  dict_file = fopen(DICT_PATH, "r");

  if(dict_file == NULL){
    fprintf(stderr, "Cannot open dictionary file, terminating");
    exit(1);
  }

  g_dict = (char**) malloc(sizeof(char*)*init_buf_len);
  g_dict_len = 0;

  for(; eof != 1;g_dict_len++){
    /* resize dict */
    if(g_dict_len>= init_buf_len){
      int new_len = init_buf_len + 20000;
      g_dict = (char**) realloc(g_dict, sizeof(char*)*new_len);
      init_buf_len = new_len;
    }
    /* read line */
    size_t n = 0;
    int res = getline(&g_dict[g_dict_len], &n, dict_file);
    if (res == -1){
      // error reading line or EOF reached
      eof = 1;
      g_dict_len--; // remove last null entry
    }
  }
}

int main(int argc, char *argv[] ){
  if(argc < 3){
    fprintf(stderr, "invalid number of arguments");
    exit(1);
  }
  read_dict(); // read dict into memory
  /* read_shadow_passwd(argv[1], argv[2]); */
  /* char* hash = crypt("damien90", g_salt); */
  /* fprintf(stderr, "%s", hash); */
  cleanup();
}
