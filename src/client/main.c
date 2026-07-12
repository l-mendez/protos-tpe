#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smcp_client.h"

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080

struct client_args {
    const char *host;
    unsigned short port;
    char admin[SMCP_TOKEN_MAX];
    char pass[SMCP_TOKEN_MAX];
    bool has_auth;
    bool verbose;
};

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-v] [-L addr] [-P port] [-a admin:pass]\n"
            "\n"
            "   -L <addr>        Management address (default: %s)\n"
            "   -P <port>        Management port (default: %d)\n"
            "   -a <admin:pass>  Admin credentials\n"
            "   -v               Show SMCP command and raw response status\n"
            "   -h               Show this help\n",
            prog, DEFAULT_HOST, DEFAULT_PORT);
}

static bool
parse_port(const char *s, unsigned short *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || errno == ERANGE || v < 1 || v > 65535) {
        return false;
    }
    *out = (unsigned short)v;
    return true;
}

static bool
copy_bounded(char *dst, size_t cap, const char *src, size_t len)
{
    if (len == 0 || len >= cap) {
        return false;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

static bool
parse_auth_arg(const char *s, char *user, size_t user_cap, char *pass, size_t pass_cap)
{
    const char *sep = strchr(s, ':');
    if (sep == NULL) {
        return false;
    }
    return copy_bounded(user, user_cap, s, (size_t)(sep - s)) &&
           copy_bounded(pass, pass_cap, sep + 1, strlen(sep + 1));
}

static void
parse_args(int argc, char **argv, struct client_args *args)
{
    args->host = DEFAULT_HOST;
    args->port = DEFAULT_PORT;
    args->admin[0] = '\0';
    args->pass[0] = '\0';
    args->has_auth = false;
    args->verbose = false;

    int c;
    while ((c = getopt(argc, argv, "hL:P:a:v")) != -1) {
        switch (c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            case 'L':
                args->host = optarg;
                break;
            case 'P':
                if (!parse_port(optarg, &args->port)) {
                    fprintf(stderr, "invalid port: %s\n", optarg);
                    exit(1);
                }
                break;
            case 'a':
                if (!parse_auth_arg(optarg, args->admin, sizeof(args->admin),
                                    args->pass, sizeof(args->pass))) {
                    fprintf(stderr, "invalid auth, expected admin:pass\n");
                    exit(1);
                }
                args->has_auth = true;
                break;
            case 'v':
                args->verbose = true;
                break;
            default:
                usage(argv[0]);
                exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "unexpected argument: %s\n", argv[optind]);
        exit(1);
    }
}

static bool
read_prompt(const char *prompt, char *buf, size_t cap, bool required)
{
    printf("%s", prompt);
    fflush(stdout);

    if (fgets(buf, cap, stdin) == NULL) {
        return false;
    }

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    } else {
        int ch;
        while ((ch = getchar()) != '\n' && ch != EOF) {
            /* descartar el resto de la línea demasiado larga */
        }
        fprintf(stderr, "input too long\n");
        return false;
    }

    if (required && buf[0] == '\0') {
        fprintf(stderr, "value is required\n");
        return false;
    }
    return true;
}

static bool
read_token_prompt(const char *prompt, char *buf, size_t cap)
{
    if (!read_prompt(prompt, buf, cap, true)) {
        return false;
    }
    if (!smcp_is_token(buf)) {
        fprintf(stderr, "value must be non-empty and contain no spaces\n");
        return false;
    }
    return true;
}

static bool
interactive_session(void)
{
    return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

static void
clear_screen(bool interactive)
{
    if (interactive) {
        printf("\033[2J\033[H");
        fflush(stdout);
    }
}

static void
pause_screen(bool interactive)
{
    char scratch[8];

    if (!interactive) {
        return;
    }
    printf("\nPress Enter to continue...");
    fflush(stdout);
    (void)fgets(scratch, sizeof(scratch), stdin);
}

static void
print_menu(void)
{
    printf("SMCP management client\n");
    printf("======================\n\n");
    printf("1: Metrics\n");
    printf("2: List users\n");
    printf("3: Add user\n");
    printf("4: Delete user\n");
    printf("5: Get config\n");
    printf("6: Set config\n");
    printf("7: Logs\n");
    printf("8: Change admin password\n");
    printf("q: Quit\n");
    fflush(stdout);
}

static bool
read_menu_choice(int *choice)
{
    char input[32];
    if (!read_prompt("> ", input, sizeof(input), true)) {
        return false;
    }
    if (strcmp(input, "q") == 0 || strcmp(input, "Q") == 0) {
        *choice = 'q';
        return true;
    }

    char *end = NULL;
    errno = 0;
    long v = strtol(input, &end, 10);
    if (end == input || *end != '\0' || errno == ERANGE || v < 1 || v > 8) {
        fprintf(stderr, "invalid option\n");
        return false;
    }
    *choice = (int)v;
    return true;
}

static bool
run_log_command(int fd, bool verbose)
{
    char count[SMCP_TOKEN_MAX];
    if (!read_prompt("count (blank for default): ", count, sizeof(count), false)) {
        return false;
    }
    if (count[0] == '\0') {
        return smcp_cmd_log(fd, NULL, verbose, stdout, stderr);
    }
    for (const char *p = count; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            fprintf(stderr, "count must be a non-negative decimal number\n");
            return false;
        }
    }
    return smcp_cmd_log(fd, count, verbose, stdout, stderr);
}

static bool
run_choice(int fd, int choice, bool verbose)
{
    char a[SMCP_TOKEN_MAX];
    char b[SMCP_TOKEN_MAX];

    switch (choice) {
        case 1:
            return smcp_cmd_metrics(fd, verbose, stdout, stderr);
        case 2:
            return smcp_cmd_list_users(fd, verbose, stdout, stderr);
        case 3:
            return read_token_prompt("user: ", a, sizeof(a)) &&
                   read_token_prompt("password: ", b, sizeof(b)) &&
                   smcp_cmd_add_user(fd, a, b, verbose, stdout, stderr);
        case 4:
            return read_token_prompt("user: ", a, sizeof(a)) &&
                   smcp_cmd_del_user(fd, a, verbose, stdout, stderr);
        case 5:
            return smcp_cmd_get_config(fd, verbose, stdout, stderr);
        case 6:
            return read_token_prompt("key: ", a, sizeof(a)) &&
                   read_token_prompt("value: ", b, sizeof(b)) &&
                   smcp_cmd_set(fd, a, b, verbose, stdout, stderr);
        case 7:
            return run_log_command(fd, verbose);
        case 8:
            return read_token_prompt("new admin password: ", a, sizeof(a)) &&
                   smcp_cmd_passwd(fd, a, verbose, stdout, stderr);
        case 'q':
            return smcp_cmd_quit(fd, verbose, stdout, stderr);
        default:
            return false;
    }
}

int
main(const int argc, char **argv)
{
    struct client_args args;
    parse_args(argc, argv, &args);
    bool interactive = interactive_session();

    if (!args.has_auth) {
        if (!read_token_prompt("admin: ", args.admin, sizeof(args.admin)) ||
            !read_token_prompt("password: ", args.pass, sizeof(args.pass))) {
            return 1;
        }
    } else if (!smcp_is_token(args.admin) || !smcp_is_token(args.pass)) {
        fprintf(stderr, "admin credentials must contain no spaces\n");
        return 1;
    }

    int fd = smcp_connect(args.host, args.port, stderr);
    if (fd < 0) {
        return 1;
    }
    if (!smcp_read_optional_greeting(fd, stderr)) {
        close(fd);
        return 1;
    }

    if (!smcp_cmd_auth(fd, args.admin, args.pass, args.verbose, stdout, stderr)) {
        close(fd);
        return 1;
    }
    pause_screen(interactive);

    while (true) {
        int choice;
        clear_screen(interactive);
        print_menu();
        if (!read_menu_choice(&choice)) {
            pause_screen(interactive);
            continue;
        }
        bool ok = run_choice(fd, choice, args.verbose);
        if (choice == 'q') {
            close(fd);
            return ok ? 0 : 1;
        }
        if (!ok) {
            close(fd);
            return 1;
        }
        pause_screen(interactive);
    }
}
