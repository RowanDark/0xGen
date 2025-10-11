# Ejecución de la batería de pruebas Go en local

Los paquetes Go de Glyph incluyen pruebas de integración que compilan binarios
auxiliares y crean subprocesos. Al ejecutar `go test ./...` en contenedores de
Linux con pocos recursos o en ejecutores de CI con límites estrictos de hilos,
el paquete `internal/plugins/runner` puede agotar la cuota de pthread disponible
mientras compila binarios temporales. El fallo se muestra como:

```
runtime/cgo: pthread_create failed: Resource temporarily unavailable
SIGABRT: abort
```

## Reducir la concurrencia para las pruebas del runner

Utiliza el siguiente comando para ejecutar la batería de forma secuencial al
tiempo que mantienes el resto de la compilación en paralelo:

```bash
GOMAXPROCS=2 go test -p=1 ./internal/plugins/runner
```

Cuando las pruebas del runner finalicen correctamente, vuelve a lanzar el resto
del conjunto con un límite de procesos mayor si es posible. Como alternativa,
combina ambos pasos reduciendo el paralelismo global al trabajar en una máquina
virtual o contenedor pequeños:

```bash
GOMAXPROCS=2 go test -p=2 ./...
```

Estos comandos reducen drásticamente el número máximo de hilos concurrentes
durante la compilación de plugins temporales, evitando el aborto y manteniendo la
misma cobertura funcional.
