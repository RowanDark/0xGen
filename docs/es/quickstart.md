# Inicio rápido: demostración de extremo a extremo

El comando `glyphctl demo` ofrece a las personas nuevas un recorrido de un minuto por la pila de Glyph.
Levanta un objetivo de demostración local, escanea la página con Seer, clasifica los hallazgos resultantes y
renderiza un informe HTML pulido. Todo se ejecuta en localhost y recurre a artefactos incluidos cuando el
acceso a la red externa está restringido.

## Requisitos previos {#prerequisites}

- Go 1.21+ (para `go run ./cmd/glyphctl demo`) o un binario `glyphctl` descargado.
- Git (para clonar este repositorio).

Todo lo demás (binarios de Glyph, Playwright, etc.) se construye a demanda. No se requieren servicios externos;
si Glyph no puede llegar a `example.com`, la demostración alimenta a Seer con una respuesta sintética que refleja
el HTML incluido en `examples/quickstart/demo-response.html`.

<div id="run-the-pipeline"></div>

La caja interactiva anterior reproduce `glyphctl demo` directamente en tu
navegador para que puedas explorar la canalización antes de instalar nada.
## Primeros pasos {#getting-started}

```bash
glyphctl demo
```

El comando realiza los siguientes pasos:

1. Sirve localmente el [objetivo de demostración]({{ config.repo_url }}/blob/main/cmd/glyphctl/demo_assets/target.html) incluido,
   de modo que no se necesita acceso a la red externa.
2. Escanea la página renderizada con Seer y guarda los hallazgos estructurados en `out/demo/findings.jsonl`.
3. Clasifica los hallazgos de manera determinista y escribe `out/demo/ranked.jsonl` para herramientas posteriores.
4. Genera un informe HTML interactivo idéntico a la referencia incluida en [`examples/quickstart/report.html`]({{ config.repo_url }}/blob/main/examples/quickstart/report.html).

Al finalizar, la terminal imprime la URL local del objetivo junto con la ruta absoluta a `out/demo/report.html`.
Abre ese archivo en tu navegador para explorar casos plegables, vistas previas en miniatura, insignias de alcance y
fragmentos de prueba de concepto listos para copiar. Los artefactos JSONL en `out/demo/` y las copias de referencia en
[`examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart) son útiles al escribir pruebas o inspeccionar los datos que emite Seer.

## Inspeccionar la ejecución {#inspecting-the-run}

Archivos útiles después de que finaliza la demostración:

| Ruta | Descripción |
| ---- | ----------- |
| `out/demo/excavator.json` | Transcripción del rastreo, incluyendo los enlaces descubiertos. |
| `out/demo/findings.jsonl` | Hallazgos sin procesar de Seer (JSONL). |
| `out/demo/ranked.jsonl` | Hallazgos clasificados con puntuaciones deterministas. |
| `out/demo/report.html` | Informe HTML final. |

El [directorio `examples/quickstart/`]({{ config.repo_url }}/tree/main/examples/quickstart) refleja las salidas esperadas para que puedas comparar ejecuciones futuras o usar datos de ejemplo en otras herramientas sin volver a ejecutar la canalización.

## Limpieza {#cleaning-up}

Elimina los artefactos generados con:

```bash
rm -rf out/demo
```

Ejecuta `glyphctl demo` nuevamente en cualquier momento para regenerar el informe.
