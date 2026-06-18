#include <stdio.h>

#include "args.h"

int
main(const int argc, char **argv)
{
    struct socks5args args;
    parse_args(argc, argv, &args);

    printf("socks5  %s:%hu\n", args.socks_addr, args.socks_port);
    printf("monitor %s:%hu\n", args.mng_addr, args.mng_port);

    return 0;
}
