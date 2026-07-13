# Pruebas de estrés

La batería de estrés verifica el requisito de al menos 500 conexiones SOCKS5
simultáneas y mide cómo cambia el throughput al aumentar la concurrencia. Es una
prueba de integración interna escrita en C11; no es una aplicación ni ofrece una
interfaz de línea de comandos.

## Entorno

Las mediciones oficiales se realizan en Linux porque el runner obtiene CPU y RSS
desde `/proc`. Desde otro sistema se debe entrar primero al contenedor:

```sh
docker compose build
docker compose run --rm dev
```

Dentro del contenedor, la única orden pública es:

```sh
make stress
```

El target compila `bin/server` y el ejecutable interno `bin/test/stress`, y luego
ejecuta siempre la batería completa. `make test` conserva únicamente pruebas
rápidas y no genera carga.

## Escenarios

- **Capacidad:** establece 500 túneles autenticados, valida 1 KiB diferente por
  túnel, los mantiene durante 10 segundos y contrasta el resultado con `METRICS`.
- **Máximo observado:** prueba incrementos de 10 hasta el primer fallo o 600 y
  refina el último intervalo. “600+” significa que el límite de esta batería se
  alcanzó sin encontrar el techo del servidor.
- **Throughput:** transfiere 64 MiB por repetición con concurrencias 1, 50, 100,
  250 y 500. Cada nivel se repite tres veces y se informa la mediana y su
  degradación frente a una conexión.
- **Soak:** mantiene 500 túneles durante 60 segundos, valida tráfico cada segundo
  y toma muestras de CPU y RSS del proceso servidor.

Backend echo, proxy y generador son procesos separados. Tanto el backend como el
generador usan `poll(2)`, por lo que su capacidad no queda limitada por
`FD_SETSIZE` y no oculta el límite del servidor basado en `select(2)`.

## Resultados

Cada ejecución crea `stress/results/<timestamp-UTC>/` con:

- `results.json`: resultado estructurado y parámetros del entorno;
- `throughput.csv`: una fila por repetición;
- `report.md`: resumen listo para incorporar al informe final;
- `server.log`, `echo.log` y `access.log`: diagnóstico de los procesos.

El directorio de resultados es local y está ignorado por Git. Un escenario falla
ante conexiones rechazadas, timeout, corrupción, métricas inconsistentes o la
terminación inesperada del servidor. No existe un umbral arbitrario de velocidad
o memoria: esos valores se informan para análisis.

## Interpretación

Las transferencias se realizan sobre loopback y generador, proxy y backend
comparten recursos de la misma máquina. Por eso los valores sirven para comparar
degradación entre niveles de concurrencia, no como capacidad absoluta de una red
real. La batería cubre IPv4 y autenticación RFC 1929; no cubre resolución FQDN.
