#include <string.h>

#include "metrics.h"

/* Estado volátil por diseño (req 6): si el servidor se reinicia, las estadísticas
 * pueden perderse. La instancia la posee el llamador (main); se accede sólo desde
 * el hilo del selector, así que no hace falta sincronización. */

void
metrics_init(struct Metrics *m)
{
    memset(m, 0, sizeof(*m));
}

void
metrics_connection_opened(struct Metrics *m)
{
    m->historical_connections++;
    m->active_connections++;
    if (m->active_connections > m->max_active_connections) {
        m->max_active_connections = m->active_connections;
    }
}

void
metrics_connection_closed(struct Metrics *m)
{
    if (m->active_connections > 0) {
        m->active_connections--;
    }
}

void
metrics_bytes_client_to_origin(struct Metrics *m, size_t n)
{
    m->bytes_client_to_origin += n;
}

void
metrics_bytes_origin_to_client(struct Metrics *m, size_t n)
{
    m->bytes_origin_to_client += n;
}
