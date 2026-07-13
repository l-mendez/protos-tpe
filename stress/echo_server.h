#ifndef STRESS_ECHO_SERVER_H
#define STRESS_ECHO_SERVER_H

#include <stdint.h>

int stress_echo_create(uint16_t *port_out);
int stress_echo_run(int listener_fd);

#endif
