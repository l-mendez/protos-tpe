#include "runner.h"

#include <stdio.h>

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) {
        fprintf(stderr, "stress test is internal; run 'make stress'\n");
        return 2;
    }
    return stress_run_all();
}
