#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <symbol.h>
#include <fr.h>
#include <util.h>

#define SAMPLES 1000000
#define THRESHOLD 100

char *monitor[] = {
  "mpih-mul.c:85",
 "mpih-mul.c:271",
  "mpih-div.c:356"
//  "mpih-mul.c:270",
 // "mpih-mul.c:121",
 // "mpih-div.c:329"
};
int nmonitor = sizeof(monitor)/sizeof(monitor[0]);

void usage(const char *prog) {
  fprintf(stderr, "Usage: %s <gpg-binary> <slot-time>\n", prog);
  exit(1);
}


int main(int ac, char **av) {
  //if (ac != 2) {printf("invalid usage"); exit(1) ;}   
 
 
 char *binary = "/home/meet/Desktop/gnupg-temp/bin/gpg";
  //if (binary == NULL)
   // usage(av[0]);
 

  int SLOT = 10000 ; 


  fr_t fr = fr_prepare();
  for (int i = 0; i < nmonitor; i++) {
    uint64_t offset = sym_getsymboloffset(binary, monitor[i]);
    if (offset == ~0ULL) {
      fprintf(stderr, "Cannot find %s in %s\n", monitor[i], binary);
      exit(1);
    } 
    fr_monitor(fr, map_offset(binary, offset));
  }

  uint16_t *res = malloc(SAMPLES * nmonitor * sizeof(uint16_t));
  for (int i = 0; i < SAMPLES * nmonitor ; i+= 4096/sizeof(uint16_t))
    res[i] = 1;
  fr_probe(fr, res);

  //int slot_time = 10000 ; 
 
  int l = fr_trace(fr, SAMPLES, res, SLOT, THRESHOLD, 0);
  for (int i = 0; i < l; i++) {
    for (int j = 0; j < nmonitor; j++)
      printf("%d ", res[i * nmonitor + j]);
    putchar('\n');
  }

  free(res);
  fr_release(fr);
}
