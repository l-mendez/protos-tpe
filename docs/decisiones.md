# Decisiones de diseño

## Protocolo SMCP

### Transporte TCP

SMCP usa TCP porque una sesión administrativa es interactiva, puede durar varios
comandos y necesita entrega confiable y ordenada de comandos y respuestas. TCP
también simplifica mantener el estado de autenticación de la sesión.

### Texto orientado a líneas

El protocolo es textual para poder depurarlo fácilmente con herramientas como
`nc` y leer las respuestas sin tooling específico. Además, el volumen de datos
administrativos es bajo, por lo que el costo de serializar texto no es relevante
frente al tráfico del proxy.

También nos permite contrastar con SOCKS5: el proxy implementa un protocolo
binario estandarizado, mientras que el canal de management prioriza inspección y
simplicidad operativa.

### Respuestas prefijadas por cantidad

Las respuestas con múltiples líneas usan `+OK <n>` seguido por exactamente `n`
líneas de datos. Esto evita usar un terminador especial como `.` y elimina la
necesidad de escaping o *dot-stuffing* si una línea de datos pudiera empezar con
ese carácter.

### Convenciones de nombres

Los comandos usan `KEBAB-CASE` en mayúsculas porque son verbos del protocolo
(`LIST-USERS`, `GET-CONFIG`, `ADD-USER`). Las claves de métricas y configuración
usan `snake_case` porque se alinean con los nombres internos de la
implementación y se leen naturalmente como pares `clave valor`.

### Registro persistente y métricas volátiles

Las métricas viven en memoria y se reinician con el servidor. El registro de
accesos, en cambio, se persiste en un archivo de texto en modo *append* porque
puede ser necesario consultarlo después de reinicios o ante reclamos externos.

El comando `LOG` no reemplaza al archivo: sólo expone las últimas líneas como una
vista cómoda desde SMCP. El archivo sigue siendo la fuente de verdad.

### Comando HELP

`HELP` se mantiene como comando del protocolo aunque el cliente interactivo no lo
muestre en el menú. Sirve para inspección manual con `nc`, pruebas rápidas y para
saber qué comandos soporta una versión del servidor sin consultar documentación
externa.
