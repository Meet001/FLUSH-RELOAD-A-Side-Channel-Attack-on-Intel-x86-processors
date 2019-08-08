#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fr.h>
#include <util.h>

int main(int ac, char **av) {
  fr_t fr = fr_prepare();

  if (ac != 2) {printf("usage: ./file-access <filename>\n"); exit(0) ; }

  void *ptr = map_offset(av[1], 0);
  fr_monitor(fr, ptr);

  uint16_t res[1];
  fr_probe(fr, res);

  for (;;) {
    fr_probe(fr, res);
    if (res[0] < 100)
      printf("%s  accessed\n", av[1]);
    delayloop(10000);
  }
}

