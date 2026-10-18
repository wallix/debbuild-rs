#include <stdio.h>

int main(void)
{
    FILE *f = fopen("/usr/share/hello-e2e/greeting", "r");
    char line[64];

    if (!f || !fgets(line, sizeof line, f))
        return 1;
    fputs(line, stdout);
    return fclose(f) != 0;
}
