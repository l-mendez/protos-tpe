#ifndef SERVER_H_Qm9vdHN0cmFwU2VydmVy
#define SERVER_H_Qm9vdHN0cmFwU2VydmVy

/**
 * Crea un socket TCP pasivo (escucha) ligado a `addr`:`port`.
 *
 * `addr` puede ser una dirección IPv4 o IPv6 en formato textual; `port` en
 * orden de host (0 deja que el sistema asigne un puerto libre). El socket se
 * deja listo para `accept`, pero el llamador es responsable de ponerlo en modo
 * no bloqueante y registrarlo en el selector.
 *
 * @return el file descriptor del socket, o -1 ante error (detalle en errno).
 */
int
server_setup_passive(const char *addr, unsigned short port);

#endif
