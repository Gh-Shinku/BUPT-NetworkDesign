#include <stdio.h>

int main()
{
  FILE *srcFile = fopen("accelerated-domains.china.conf", "r");
  FILE *dstFile = fopen("testfile.txt", "w");

  char str[128];
  int idx = -1;
  char ch;
  while ((ch = fgetc(srcFile)) != EOF) {
    if (idx == -1) {
      if (ch == '/')
        ++idx;
    } else {
      if (ch == '/') {
        str[idx] = '\0';
        fprintf(dstFile, "%s A\n", str);
        idx = -1;
      } else {
        str[idx++] = ch;
      }
    }
  }

  fclose(srcFile);
  fclose(dstFile);
  return 0;
}