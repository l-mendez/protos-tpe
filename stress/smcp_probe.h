#ifndef STRESS_SMCP_PROBE_H
#define STRESS_SMCP_PROBE_H

#include "stress_helpers.h"

#include <stdbool.h>
#include <stdint.h>

bool stress_smcp_query_metrics(uint16_t port, struct stress_metrics *metrics);

#endif
