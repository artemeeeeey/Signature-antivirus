#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//FIMOZ RULIT!!!
void
hexdump (unsigned long bse, char *buf, int len)
{
  int pos;
  char line[80];
  
  while (len > 0)
    {
      int cnt, i;

      pos = 0;
      cnt = 16;
      if (cnt > len)
        cnt = len;

      for (i = 0; i < cnt; i++)
        {
          pos += snprintf (&line[pos], sizeof (line) - pos,
                                "%02x ", (unsigned char) buf[i]);
        }
      printf ("%s\n", line);

      bse += 16;
      buf += 16;
      len -= cnt;
    }
}

int main(int argc, char* argv[]){
    FILE *f = fopen(argv[1], "r");
    char k1ll3d[800];
    while (!feof(f)){
        fgets(k1ll3d, sizeof(k1ll3d), f);
        hexdump(16, k1ll3d, sizeof(k1ll3d));
    }
    return 0;
}