#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_PORT 8080

#define TOKEN_MAX 256
#define LINE_MAX_LEN 4096

struct client_args {
    const char *host;
    unsigned short port;
    char admin[TOKEN_MAX];
    char pass[TOKEN_MAX];
    bool has_auth;
};

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-L addr] [-P port] [-a admin:pass]\n"
            "\n"
            "   -L <addr>        Management address (default: %s)\n"
            "   -P <port>        Management port (default: %u)\n"
            "   -a <admin:pass>  Admin credentials\n"
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

    int c;
    while ((c = getopt(argc, argv, "hL:P:a:")) != -1) {
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
is_token(const char *s)
{
    if (s[0] == '\0') {
        return false;
    }
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (isspace(c) || c < 0x21 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

static bool
read_token_prompt(const char *prompt, char *buf, size_t cap)
{
    if (!read_prompt(prompt, buf, cap, true)) {
        return false;
    }
    if (!is_token(buf)) {
        fprintf(stderr, "value must be non-empty and contain no spaces\n");
        return false;
    }
    return true;
}

static int
connect_smcp(const char *host, unsigned short port)
{
    char port_s[6];
    snprintf(port_s, sizeof(port_s), "%hu", port);

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_NUMERICSERV,
    };

    struct addrinfo *list;
    int gai = getaddrinfo(host, port_s, &hints, &list);
    if (gai != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *rp = list; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(list);

    if (fd < 0) {
        perror("connect");
    }
    return fd;
}

static bool
send_all(int fd, const char *s)
{
    size_t off = 0;
    size_t len = strlen(s);
    while (off < len) {
        ssize_t n = send(fd, s + off, len - off, 0);
        if (n > 0) {
            off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else {
            perror("send");
            return false;
        }
    }
    return true;
}

static bool
read_line(int fd, char *buf, size_t cap)
{
    size_t len = 0;
    while (len + 1 < cap) {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n > 0) {
            if (c == '\n') {
                if (len > 0 && buf[len - 1] == '\r') {
                    len--;
                }
                buf[len] = '\0';
                return true;
            }
            buf[len++] = c;
        } else if (n == 0) {
            fprintf(stderr, "server closed the connection\n");
            return false;
        } else if (errno != EINTR) {
            perror("recv");
            return false;
        }
    }
    fprintf(stderr, "response line too long\n");
    return false;
}

static bool
optional_greeting_waiting(int fd)
{
    fd_set set;
    FD_ZERO(&set);
    FD_SET(fd, &set);

    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    int ready = select(fd + 1, &set, NULL, NULL, &tv);
    return ready > 0 && FD_ISSET(fd, &set);
}

static bool
read_optional_greeting(int fd)
{
    if (!optional_greeting_waiting(fd)) {
        return true;
    }

    char line[LINE_MAX_LEN];
    if (!read_line(fd, line, sizeof(line))) {
        return false;
    }
    if (strncmp(line, "+OK SMCP ", 9) == 0) {
        return true;
    }

    fprintf(stderr, "unexpected greeting: %s\n", line);
    return false;
}

static bool
parse_count_status(const char *line, unsigned long *out)
{
    if (strncmp(line, "+OK ", 4) != 0 || !isdigit((unsigned char)line[4])) {
        return false;
    }

    char *end = NULL;
    errno = 0;
    unsigned long n = strtoul(line + 4, &end, 10);
    if (errno == ERANGE || *end != '\0') {
        return false;
    }
    *out = n;
    return true;
}

static bool
run_command(int fd, const char *command)
{
    char wire[LINE_MAX_LEN];
    int n = snprintf(wire, sizeof(wire), "%s\n", command);
    if (n < 0 || (size_t)n >= sizeof(wire)) {
        fprintf(stderr, "command too long\n");
        return false;
    }
    if (!send_all(fd, wire)) {
        return false;
    }

    char line[LINE_MAX_LEN];
    if (!read_line(fd, line, sizeof(line))) {
        return false;
    }

    if (strncmp(line, "-ERR ", 5) == 0) {
        fprintf(stderr, "%s\n", line);
        return false;
    }
    if (strncmp(line, "+OK", 3) != 0) {
        fprintf(stderr, "malformed response: %s\n", line);
        return false;
    }

    unsigned long count;
    if (parse_count_status(line, &count)) {
        for (unsigned long i = 0; i < count; i++) {
            if (!read_line(fd, line, sizeof(line))) {
                return false;
            }
            printf("%s\n", line);
        }
    } else {
        printf("%s\n", line);
    }
    return true;
}

static bool
build_command(char *dst, size_t cap, const char *fmt, const char *a, const char *b)
{
    int n = b == NULL ? snprintf(dst, cap, fmt, a) : snprintf(dst, cap, fmt, a, b);
    if (n < 0 || (size_t)n >= cap) {
        fprintf(stderr, "command too long\n");
        return false;
    }
    return true;
}

static void
print_menu(void)
{
    printf("\n");
    printf("1: Metrics\n");
    printf("2: List users\n");
    printf("3: Add user\n");
    printf("4: Delete user\n");
    printf("5: Get config\n");
    printf("6: Set config\n");
    printf("7: Logs\n");
    printf("8: Change admin password\n");
    printf("9: Help\n");
    printf("0: Quit\n");
}

static bool
read_menu_choice(int *choice)
{
    char input[32];
    if (!read_prompt("> ", input, sizeof(input), true)) {
        return false;
    }

    char *end = NULL;
    errno = 0;
    long v = strtol(input, &end, 10);
    if (end == input || *end != '\0' || errno == ERANGE || v < 0 || v > 9) {
        fprintf(stderr, "invalid option\n");
        return false;
    }
    *choice = (int)v;
    return true;
}

static bool
read_log_command(char *cmd, size_t cap)
{
    char count[TOKEN_MAX];
    if (!read_prompt("count (blank for default): ", count, sizeof(count), false)) {
        return false;
    }
    if (count[0] == '\0') {
        snprintf(cmd, cap, "LOG");
        return true;
    }
    for (const char *p = count; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            fprintf(stderr, "count must be a non-negative decimal number\n");
            return false;
        }
    }
    return build_command(cmd, cap, "LOG %s", count, NULL);
}

static bool
command_from_choice(int choice, char *cmd, size_t cap)
{
    char a[TOKEN_MAX];
    char b[TOKEN_MAX];

    switch (choice) {
        case 1:
            snprintf(cmd, cap, "METRICS");
            return true;
        case 2:
            snprintf(cmd, cap, "LIST-USERS");
            return true;
        case 3:
            return read_token_prompt("user: ", a, sizeof(a)) &&
                   read_token_prompt("password: ", b, sizeof(b)) &&
                   build_command(cmd, cap, "ADD-USER %s %s", a, b);
        case 4:
            return read_token_prompt("user: ", a, sizeof(a)) &&
                   build_command(cmd, cap, "DEL-USER %s", a, NULL);
        case 5:
            snprintf(cmd, cap, "GET-CONFIG");
            return true;
        case 6:
            return read_token_prompt("key: ", a, sizeof(a)) &&
                   read_token_prompt("value: ", b, sizeof(b)) &&
                   build_command(cmd, cap, "SET %s %s", a, b);
        case 7:
            return read_log_command(cmd, cap);
        case 8:
            return read_token_prompt("new admin password: ", a, sizeof(a)) &&
                   build_command(cmd, cap, "PASSWD %s", a, NULL);
        case 9:
            snprintf(cmd, cap, "HELP");
            return true;
        case 0:
            snprintf(cmd, cap, "QUIT");
            return true;
        default:
            return false;
    }
}

int
main(const int argc, char **argv)
{
    struct client_args args;
    parse_args(argc, argv, &args);

    if (!args.has_auth) {
        if (!read_token_prompt("admin: ", args.admin, sizeof(args.admin)) ||
            !read_token_prompt("password: ", args.pass, sizeof(args.pass))) {
            return 1;
        }
    } else if (!is_token(args.admin) || !is_token(args.pass)) {
        fprintf(stderr, "admin credentials must contain no spaces\n");
        return 1;
    }

    int fd = connect_smcp(args.host, args.port);
    if (fd < 0) {
        return 1;
    }
    if (!read_optional_greeting(fd)) {
        close(fd);
        return 1;
    }

    char cmd[LINE_MAX_LEN];
    if (!build_command(cmd, sizeof(cmd), "AUTH %s %s", args.admin, args.pass) ||
        !run_command(fd, cmd)) {
        close(fd);
        return 1;
    }

    while (true) {
        int choice;
        print_menu();
        if (!read_menu_choice(&choice)) {
            continue;
        }
        if (!command_from_choice(choice, cmd, sizeof(cmd))) {
            continue;
        }
        bool ok = run_command(fd, cmd);
        if (choice == 0) {
            close(fd);
            return ok ? 0 : 1;
        }
        if (!ok) {
            close(fd);
            return 1;
        }
    }
}
