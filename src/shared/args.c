#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <stdbool.h>
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "args.h"

static unsigned short
port(const char* s)
{
    char* end = 0;
    errno = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 1 || sl > USHRT_MAX)
    {
        fprintf(stderr, "el puerto debe estar en el rango 1-65535: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static void
user(char* s, struct User* user)
{
    char* p = strchr(s, ':');
    if (p == NULL)
    {
        fprintf(stderr, "password not found\n");
        exit(1);
    }
    else
    {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
    }
}

static void
usage(const char* progname, int users)
{
    fprintf(stderr,
            "Uso: %s [OPCIÓN]...\n"
            "\n"
            "   -h               Imprime la ayuda y termina.\n"
            "   -l <SOCKS addr>  Dirección donde servirá el proxy SOCKS.\n"
            "   -L <conf  addr>  Dirección donde servirá el servicio de management.\n"
            "   -p <SOCKS port>  Puerto de escucha del proxy SOCKS.\n"
            "   -P <conf port>   Puerto de escucha del servicio de management.\n"
            "   -u <name>:<pass> Usuario y contraseña habilitados para usar el proxy. Hasta %d.\n"
            "   -a <name>:<pass> Usuario y contraseña del administrador.\n"
            "   -o <path>        Archivo de registro de accesos (default: access.log).\n"

            "\n",
            progname, users);
    exit(1);
}

void
parse_args(const int argc, char** argv, struct socks5args* args)
{
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_addr = "0.0.0.0";
    args->socks_port = 1080;

    args->mng_addr = "127.0.0.1";
    args->mng_port = 8080;

    args->access_log_path = "access.log";

    int c;
    int nusers = 0;
    opterr = 0;

    while (true)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hl:L:p:P:u:a:o:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0], MAX_USERS);
            break;
        case 'l':
            args->socks_addr = optarg;
            break;
        case 'L':
            args->mng_addr = optarg;
            break;
        case 'p':
            args->socks_port = port(optarg);
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'u':
            if (nusers >= MAX_USERS)
            {
                fprintf(stderr, "maximum number of command line users reached: %d.\n", MAX_USERS);
                exit(1);
            }
            else
            {
                user(optarg, args->users + nusers);
                nusers++;
            }
            break;
        case 'a':
            user(optarg, &args->admin);
            break;
        case 'o':
            args->access_log_path = optarg;
            break;
        default:
            if (optopt != 0) {
                fprintf(stderr, "opción inválida o incompleta: -%c\n", optopt);
            } else {
                fprintf(stderr, "opción inválida.\n");
            }
            exit(1);
        }
    }
    if (optind < argc)
    {
        fprintf(stderr, "argumento no aceptado: ");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
