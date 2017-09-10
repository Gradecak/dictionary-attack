#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include <crypt.h>

//Forward declrations
typedef struct Account Account;
typedef struct Name Name;
typedef struct Password Password;
typedef struct T_data T_data;
typedef enum { false, true } bool;
void attack(char*, char*);
void read_dict();
void read_common_passwds();
void parse_shadow(char*);
void parse_accounts(FILE*, FILE*);
Name* parse_name(char*);
Account* parse_accounts_entry(char*, char*);
void cleanup();
bool name_permutations(Account*);
void* search_dict(void*);
/******************************************/

//globals
char*      g_salt;
char**     g_dict;
Password** g_common_passwds = NULL;
int        g_dict_len;
Account**  g_accounts;
int        g_accounts_len;
/******************************************/

// CONSTS (CONFIG)
#define NUM_THREADS      = 2;
const char* DICT_PATH    = "./output.txt";
const char* TOP_250_PATH = "./dictionary/top250.txt";


/******************************************/

struct T_data{
  int low;
  int high;
  long t_id;
};

struct Name {
  char** names;
};

struct Account{
  bool solved;
  Name* name;
  char* username;
  char* passwd_hash;
};

struct Password{
  char* plain;
  char* hash;
};

Name* parse_name(char* passwd_entry){
  Name* name = malloc(sizeof(Name*));
  // at most someone will have 4 names
  name->names = malloc(sizeof(char*) * 4);
  char* name_string = strdup(passwd_entry);
  char* p;
  p = strtok(name_string, ":");
  for(int i=0; i<4; i++){
    p = strtok(NULL, ":");
  }
  char* x = strndup(p, strlen(p) -3); // exclude ,,, from name
  char* y;
  y = strtok(x, " ");
  for(int i=0; y != NULL; i++){
    y[0] = tolower(y[0]);
    name->names[i] = y;
    y = strtok(NULL, " ");
  }
  return name;
}

Account* parse_accounts_entry(char* shadow_line, char* passwd_line){
  Account* acc = malloc(sizeof(Account*));
  acc->username = malloc(sizeof(char*) * 7);  /* 7 chars (username(6) + null(1)) */
  acc->passwd_hash = malloc(sizeof(char*)*29); /* 28char hash + \0 */
  acc->name = parse_name(passwd_line);
  acc->solved = false;
  /* parse entries according to username and hash length patterns*/
  acc->username = strndup(passwd_line, 6);
  acc->passwd_hash = strndup(&shadow_line[7], 28);
  //check user against common passwords
  for(int i=0; i<250; i++){
    int res = strcmp(acc->passwd_hash, g_common_passwds[i]->hash);

    if(res == 0){
      /* printf("%s:%s\n", acc->username, g_common_passwds[i]->plain); */
      fflush(stdout);
      acc->solved = true;
    }
  }
  /* try combinations of users name */
  if(!acc->solved){
    bool solved = name_permutations(acc);
    acc->solved = solved;
  }
  free(acc->name->names);
  return acc;
}

char* concat(char* str1, char* str2){
  int i = (strlen(str1) + strlen(str2)) +1;
  char* zor = malloc(sizeof(char) * i);
  strcat(zor, str1);
  strcat(zor, str2);
  return zor;
}

char* upper(char* str){
  char* new_s = strdup(str);
  for(int i=0; new_s[i] != '\0'; ++i){
    new_s[i] = toupper(new_s[i]);
  }
  return new_s;
}

bool check_password(Account* acc, char pass[]){
  bool solved = false;
  char* hash = crypt(pass, g_salt);
  int result = strcmp(hash, acc->passwd_hash);
  if(result == 0){
    printf("%s:%s\n",acc->username,pass);
    fflush(stdout);
    solved = true;
  }
  return solved;
}

bool name_permutations(Account* acc){
  bool solved = false;
  int perms_len = 3;
  for(int i=0; i<4; i++){
    int name_len = strlen(acc->name->names[i]);
    char* permutations[perms_len];
    if(acc->name->names[i] != NULL){
      permutations[0] = concat(acc->name->names[i], "xor");
      permutations[1] = concat(acc->name->names[i], "zorz");
      permutations[2] = upper(acc->name->names[i]);
      for(int j=0; j < perms_len; ++j){
        solved = check_password(acc, permutations[j]);
        /* free(permutations[j]); */
      }
    }
  }
  /* free(permutations); */
  return solved;
}

void parse_accounts(FILE* shadow_f, FILE* passwd_f){
  int init_accounts_len = 10000;
  g_accounts = malloc(sizeof(Account*) * init_accounts_len);
  g_accounts_len = 0;
  int eof = 0;
  for(;eof != 1; g_accounts_len++){
    if(g_accounts_len >= init_accounts_len){
      int new_len = init_accounts_len + 20000;
      g_accounts = (Account**) realloc(g_accounts, sizeof(Account*) * new_len);
      init_accounts_len = new_len;
    }
    /* read line */
    size_t n = 0;
    char* shadow_entry = NULL;
    char* passwd_entry = NULL;
    int res = getline(&shadow_entry, &n, shadow_f);
    n = 0;
    int res1 = getline(&passwd_entry, &n, passwd_f);
    if (res == -1 || res1 == -1){
      // error reading line or EOF reached
      eof = 1;
      g_accounts_len--; // remove last null entry
    }
    else{
      Account * a = parse_accounts_entry(shadow_entry, passwd_entry);
      if(!a->solved){
        g_accounts[g_accounts_len] = a;
        g_accounts_len++;
      }
    }
  }
}

void set_salt(char* shadow_entry){
  g_salt = malloc(strlen(shadow_entry));
  strncpy(g_salt, &shadow_entry[7], 6);
  g_salt[6] = '\0';
  /* fprintf(stderr, "salt %s", g_salt); */
}

void attack(char* shadow_path, char* passwd_path){
  FILE* shadow_file;
  FILE* passwd_file;

  shadow_file = fopen(shadow_path, "r");
  passwd_file = fopen(passwd_path, "r");

  if(shadow_file == NULL || passwd_file == NULL){
    fprintf(stderr, "shadow file or passwd file incorrect path!");
    exit(1);
  }

  char* shadow_line = NULL;
  size_t len = 0;
  getline(&shadow_line, &len, shadow_file);
  rewind(shadow_file);
  set_salt(shadow_line);
  read_common_passwds();
  parse_accounts(shadow_file, passwd_file);
  read_dict();
}

void cleanup(){
  for(int i=0; i<g_dict_len;i++){
    free(g_dict[i]);
  }
  free(g_dict);
  free(g_salt);
  for(int i=0; i<251;i++){
    free(g_common_passwds[i]);
  }
  free(g_common_passwds);
}

void read_common_passwds(){
  fprintf(stderr, "reading common passwords\n");
  FILE* common_pswds;
  common_pswds = fopen(TOP_250_PATH, "r");
  if(common_pswds == NULL){
    fprintf(stderr, "Couldn't open top 250 file for reading\n");
  }
  g_common_passwds = malloc(sizeof(Password*) * 250);
  for(int i=0; i<250; i++){
    Password* passwd = malloc(sizeof(Password));
    passwd->plain = NULL;
    char* line = NULL;
    size_t n = 0;
    int res = getline(&line, &n, common_pswds);
    if(res == -1){
      fprintf(stderr,"error reading line (or eof reached)");
    }
    size_t x = strlen(line);
    passwd->plain = strndup(line, x-2);
    struct crypt_data* d = malloc(sizeof(struct crypt_data));
    d->initialized = 0;
    passwd->hash = crypt_r(passwd->plain, g_salt, d);
    g_common_passwds[i] = passwd;
  }
}

void* search_dict(void* data){
  T_data* t_data = data;
  struct crypt_data d;
  d.initialized = 0;
  for(int i=t_data->low; i<t_data->high; i++){
    char* hash = crypt_r(&g_dict[i], g_salt, d);
    for(int j=0; j<g_accounts_len; j++){
      if(!g_accounts[j]->solved){
        int res = strcmp(hash, g_accounts[j]->passwd_hash);
        if(res == 0){
          printf("%s:%s\n", g_accounts[j]->username, g_dict[i]);
          fflush(stdout);
          g_accounts[j]->solved = true;
        }
      }
    }
  }
  pthread_exit(NULL);
}

void read_dict(){
  int init_buf_len = 50000; //50,000 lines
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
    char* line = NULL;
    int res = getline(&line, &n, dict_file);
    g_dict[g_dict_len] = strndup(line, strlen(line)-1);
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
  attack(argv[1], argv[2]);
  cleanup();
}
