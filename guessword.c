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
typedef struct Map_elem Map_elem;
typedef Map_elem* Map;
typedef enum { false, true } bool;
void attack(char*, char*);
/* file reads */
char** read_dict(const char*, int*);
void read_common_passwds();

/* parsers */
void parse_shadow(char*);
void parse_accounts(FILE*, FILE*);
Name* parse_name(char*);
Account* parse_accounts_entry(char*, char*);

char* name_permutations(Account*);
void start_threads();

/* threaded functions */
void* search_dict_with_caps_perm(void*);
void* search_dict(void*);
void* check_names(void*);

/* helpers  */
char* concat(char*, char*);
bool check_caps_perms(Account*, char*, struct crypt_data*);
bool check_password(Account*, char*, struct crypt_data*);
void cleanup();
/******************************************/

//globals
char*      g_salt;
char**     g_dict;
char**     g_combined;
char**     g_leet;
Password** g_common_passwds = NULL;
int        g_dict_len;
int        g_combined_len;
int        g_leet_len;
Account**  g_accounts;
int        g_accounts_len;
/******************************************/

// CONSTS (CONFIG)
#define NUM_DICT_THREADS      2
#define NUM_LEET_THREADS      2
#define NUM_NAME_THREADS      2
#define NUM_COMBO_THREADS     2

const char* DICT_PATH          = "./standard.txt";
const char* LEET_DICT_PATH     = "./leet.txt";
const char* COMBINED_DICT_PATH = "./combined.txt";
const char* TOP_250_PATH       = "./dictionary/top250.txt";


/******************************************/

struct T_data{
  int low;
  int high;
  long t_id;
  void* dict;
};

struct m_Entry{
  char* key;
  char** vals;
};

struct Name {
  char** names;
  int len;
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

char* concat(char* str1, char* str2){
  int i = (strlen(str1) + strlen(str2)) +1;
  char* zor = malloc(sizeof(char) * i);
  strcat(zor, str1);
  strcat(zor, str2);
  return zor;
}

void print_dict_test(){
  if(g_dict )
  for(int i=0; i<g_dict_len; i++){
    fprintf(stderr, "%s", g_dict[i]);
  }
}

bool check_caps_perms(Account* acc, char* name, struct crypt_data* d){
  char* new_s = strdup(name);
  bool solved = false;
  for(int i=0; new_s[i] != '\0'; i++){
    new_s[i] = toupper(new_s[i]);
    solved = check_password(acc, new_s, d);
    if(solved) break;
    else new_s[i] = tolower(new_s[i]);
  }
  if( !solved){
    for(int i=0; new_s[i] != '\0'; i++){
      new_s[i] = toupper(new_s[i]);
    }
    solved = check_password(acc, new_s, d);
  }
  free(new_s);
  return solved;
}

bool check_password(Account* acc, char* pass, struct crypt_data* d){
  bool solved = false;
  char* hash = crypt_r(pass, g_salt, d);
  int result = strcmp(hash, acc->passwd_hash);
  if(result == 0){
    acc->solved = true;
    printf("%s:%s\n", acc->username, pass);
    fflush(stdout);
    solved = true;
  }
  return solved;
}

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
  int len = 0;
  for(int i=0; y != NULL; i++){
    y[0] = tolower(y[0]);
    name->names[i] = y;
    y = strtok(NULL, " ");
    len++;
  }
  name->len = len;
  return name;
}

Account* parse_accounts_entry(char* shadow_line, char* passwd_line){
  Account* acc = malloc(sizeof(Account*));
  acc->name = parse_name(passwd_line);
  acc->solved = false;
  /* parse entries according to username and hash length patterns*/
  acc->username = strndup(passwd_line, 6);
  acc->passwd_hash = strndup(&shadow_line[7], 28);
  //check user against common passwords
  for(int i=0; i<250; i++){
    int res = strcmp(acc->passwd_hash, g_common_passwds[i]->hash);
    if(res == 0){
      printf("%s:%s\n", acc->username, g_common_passwds[i]->plain);
      fflush(stdout);
      acc->solved = true;
    }
  }
  /* try combinations of users name */
  /* if(!acc->solved){ */
  /*   bool solved = name_permutations(acc); */
  /*   acc->solved = solved; */
  /* } */
  return acc;
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
      Account* a = parse_accounts_entry(shadow_entry, passwd_entry);
      if(!a->solved){
        g_accounts[g_accounts_len] = a;
        /* g_accounts_len++; */
      }
      else g_accounts_len--;
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
  int rc = getline(&shadow_line, &len, shadow_file);
  if (rc == -1){
    fprintf(stderr, "Error reading shadow file");
    exit(-1);
  }
  rewind(shadow_file);
  set_salt(shadow_line);
  read_common_passwds();
  parse_accounts(shadow_file, passwd_file);
  /* read dictionaries into memory */
  g_dict = read_dict(DICT_PATH,  &g_dict_len);
  g_combined = read_dict(COMBINED_DICT_PATH, &g_combined_len);
  g_leet = read_dict(LEET_DICT_PATH, &g_leet_len);
  /* ruuuun */
  start_threads();
}

void cleanup(){
  fprintf(stderr, "*************** CLEANING UP *********************");
  for(int i=0; i<g_dict_len;i++){
    free(g_dict[i]);
  }
  free(g_dict);
  free(g_salt);
  for(int i=0; i<251;i++){
    free(g_common_passwds[i]);
  }
  free(g_common_passwds);
  for(int i=0; i<g_accounts_len; i++){
    free(g_accounts[i]);
  }
  free(g_accounts);
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

void* check_names(void* args){
  T_data* t_data = (T_data*) args;
  Account** accounts = (Account**) t_data->dict;
  fprintf(stderr, "started thread %ld \n", t_data->t_id);
  struct crypt_data* d = malloc(sizeof(struct crypt_data));
  d->initialized = 0;
  for(int i=t_data->low; i<t_data->high; i++){
    Account* acc = accounts[i];
    if(acc->solved == false){
      for(int j=0; j<acc->name->len;j++){
        if(check_password(acc, acc->name->names[j], d)) break;
        char* perm = NULL;
        perm = concat(acc->name->names[j], "xor");
        if(check_password(acc, perm, d)) break;
        /* free(perm); */
        perm = concat(acc->name->names[j], "zorz");
        if(check_password(acc, perm, d)) break;
        if(check_caps_perms(acc, acc->name->names[j], d)) break;
      }
    }
  }
  pthread_exit(NULL);
}

void* search_dict(void* data){
  T_data* t_data = (T_data*) data;
  fprintf(stderr, "started thread %ld \n", t_data->t_id);
  struct crypt_data* d = malloc(sizeof(struct crypt_data));
  char** dict = (char**) t_data->dict;
  d->initialized = 0;
  for(int i=t_data->low; i<t_data->high; i++ ){
    char* hash = crypt_r(dict[i], g_salt, d);
    for(int j=0; j<g_accounts_len; j++){
      if(!g_accounts[j]->solved){
        int res = strcmp(hash, g_accounts[j]->passwd_hash);
        if(res == 0){
          printf("%s:%s\n", g_accounts[j]->username, dict[i]);
          fflush(stdout);
          g_accounts[j]->solved = true;
          break;
        }
      }
    }
  }
  pthread_exit(NULL);
}

void* search_dict_with_caps_perm(void* data){
  T_data* t_data = (T_data*) data;
  fprintf(stderr, "started thread %ld \n", t_data->t_id);
  struct crypt_data* d = malloc(sizeof(struct crypt_data));
  d->initialized = 0;
  for(int i=t_data->low; i<t_data->high; i++){
    int len = strlen(g_dict[i]);
    /* loop caps permutations  */
    char* upper = strdup(g_dict[i]);
    for(int k=0; k<len+4; k++){
      char* a = strdup(g_dict[i]);
      /*try combinations of random upercase letters*/
      if(k < len){
        a[k] = toupper(a[k]);
        upper[k] = toupper(upper[k]);
      }
      /* try all uppercase string */
      else if (k == len){
        a = upper;
      }
      /* try regular lowercase string */
      else if (k == len +1){
        a = g_dict[i];
      }
      /* try 'xor' string */
      else if (k == len +2){
        a = concat(g_dict[i], "xor");
      }
      /* try 'zorz' string*/
      else if (k == len +3){
        a = concat(g_dict[i], "zorz");
      }
      char* hash = crypt_r(a, g_salt, d);
      for(int j=0; j<g_accounts_len; j++){
        if(!g_accounts[j]->solved){
          int res = strcmp(hash, g_accounts[j]->passwd_hash);
          if(res == 0){
            printf("%s:%s\n", g_accounts[j]->username, a);
            fflush(stdout);
            g_accounts[j]->solved = true;
            break;
          }
        }
      }
      /* free(a); */
    }
    free(upper);
  }
  pthread_exit(NULL);
}

void start_threads(){
  int total_threads = NUM_DICT_THREADS + NUM_NAME_THREADS + NUM_COMBO_THREADS + NUM_LEET_THREADS;
  pthread_t threads[total_threads];
  int section_length = g_dict_len/(NUM_DICT_THREADS);
  int r;
  int t_id = 0;
  //start dictionary threads
  for(int t=0;t<NUM_DICT_THREADS;t++){
    T_data* data = malloc(sizeof(T_data*));
    data->low = t*section_length;
    data->high = (t+1) * section_length;
    data->t_id = t_id;
    data->dict = g_dict;
    r = pthread_create(&threads[t_id], NULL, search_dict_with_caps_perm, (void*)data);
    if(r){
      fprintf(stderr, "couldn't start thread!!! \n");
      exit(1);
    }
    t_id++;
  }
  fprintf(stderr, "********* starting from t_id %d", t_id);
  /* start name threads */
  section_length = g_accounts_len/(NUM_NAME_THREADS);
  for(int t=0; t<NUM_NAME_THREADS; t++){
    T_data* data = malloc(sizeof(T_data*));
    data->low =t * section_length;
    data->high = (t+1) * section_length;
    data->t_id = t_id;
    data->dict = g_accounts;
    fprintf(stderr, "ABOUT TO START THREAD t_id %d", t_id);
    r = pthread_create(&threads[t_id], NULL, check_names, (void*) data);
    if(r){
      fprintf(stderr, "couldn't start thread!!! \n");
      exit(1);
    }
    t_id++;
  }
  /* start leet threads */
  section_length = g_leet_len/NUM_LEET_THREADS;
  for(int t=0; t<NUM_LEET_THREADS; t++){
    T_data* data = malloc(sizeof(T_data*));
    data->low =t * section_length;
    data->high = (t+1) * section_length;
    data->t_id = t_id;
    data->dict = g_leet;
    r = pthread_create(&threads[t_id], NULL, search_dict, (void*) data);
    if(r){
      fprintf(stderr, "couldn't start thread!!! \n");
      exit(1);
    }
    t_id++;
  }
  section_length = g_combined_len/NUM_COMBO_THREADS;
  for(int t=0; t<NUM_COMBO_THREADS; t++){
    T_data* data = malloc(sizeof(T_data*));
    data->low =t * section_length;
    data->high = (t+1) * section_length;
    data->t_id = t_id;
    data->dict = g_combined;
    r = pthread_create(&threads[data->t_id], NULL, search_dict, (void*) data);
    if(r){
      fprintf(stderr, "couldn't start thread!!! \n");
      exit(1);
    }
    t_id++;
  }
  /*wait for threads to finish*/
  for (int i = 0; i < total_threads; i++){
    pthread_join(threads[i], NULL);
  }
}

char** read_dict(const char* file_name, int* len_ptr){
  int init_buf_len = 50000; //50,000 lines
  int eof = 0;
  FILE* dict_file;
  dict_file = fopen(file_name, "r");
  if(dict_file == NULL){
    fprintf(stderr, "Cannot open dictionary file, terminating");
    exit(1);
  }
  char** dict = (char**) malloc(sizeof(char*)*init_buf_len);
  int x = 0;
  for(; eof != 1; x++){
    /* resize dict */
    if(x >= init_buf_len){
      int new_len = init_buf_len + 20000;
      dict = (char**) realloc(dict, sizeof(char*)*new_len);
      init_buf_len = new_len;
    }
    /* read line */
    size_t n = 0;
    char* line = NULL;
    int res = getline(&line, &n, dict_file);
    dict[x] = strndup(line, strlen(line)-1);
    if (res == -1){
      // error reading line or EOF reached
      eof = 1;
      x--; // remove last null entry
    }
  }
  *len_ptr = x;
  return dict;
}

int main(int argc, char *argv[] ){
  if(argc < 3){
    fprintf(stderr, "invalid number of arguments");
    exit(1);
  }
  attack(argv[1], argv[2]);
  /* cleanup(); */
}
