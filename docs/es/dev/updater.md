# Canales de actualización y reversión

0xgen incluye un servicio de actualización automática para la aplicación de
escritorio y para la CLI `glyphctl`. Este documento describe cómo publicamos en
los canales estable y beta, cómo generamos paquetes delta y cómo los clientes
verifican, aplican y revierten actualizaciones de forma segura.

## Canales de distribución {#release-channels}

Mantenemos dos canales públicos:

- **Estable**: opción predeterminada para producción. Las versiones llegan aquí
  después de superar las pruebas de humo en todas las plataformas.
- **Beta**: compilaciones optativas para quienes quieren probar funciones
  anticipadamente. Se publican en cuanto finaliza la automatización de la
  liberación para detectar regresiones antes de ascender a estable.

### Selector de canal en el escritorio {#desktop-channel-selection}

La aplicación muestra el canal activo en Configuración → Actualizaciones. El
usuario puede cambiar entre Estable y Beta; al confirmar se ejecuta una búsqueda
inmediata de actualizaciones y se descarga lo necesario. El valor se guarda en la
configuración del usuario para futuras comprobaciones automáticas.

### Indicador de canal en la CLI {#cli-channel-flag}

`glyphctl` expone el comando `self-update` con la opción
`--channel=<stable|beta>`. El valor predeterminado es el canal almacenado y la
opción funciona como un override temporal. Para cambiar la preferencia persistida
ejecuta `glyphctl self-update channel <stable|beta>`; guardamos el resultado en
`~/.config/glyphctl/updater.json` junto con los datos necesarios para la
reversión. `glyphctl self-update channel` sin argumentos imprime el canal activo.

El updater conserva el binario anterior en el mismo directorio de configuración.
`glyphctl self-update --rollback` restaura esa copia y restablece el canal a
`stable` como medida de seguridad.

Ambos clientes incluyen el canal en los encabezados de la petición. La API de
actualizaciones devuelve el manifiesto correspondiente a esa cohorte.

## Paquetes delta {#delta-update-packaging}

La automatización de releases produce paquetes delta además de los instaladores
completos. Actualmente admitimos:

- **macOS**: parches binarios entre paquetes `.app` firmados usando `bsdiff`
  mediante las utilidades de Sparkle.
- **Windows**: los MSI incluyen una transformación de parche para aplicar
  archivos `.msp` in situ.
- **Linux**: las AppImage se publican con metadatos `zsync` para descargas
  eficientes a nivel de bloque.

Si el delta supera el 60 % del tamaño del instalador completo o la plataforma no
figura en la lista anterior, el manifiesto marca `delta_available = false` y los
clientes recurren al instalador completo.

## Manifiestos firmados {#signed-manifests}

Cada canal publica un manifiesto JSON con los números de versión y las sumas de
verificación de los artefactos completos y delta. La tubería firma el manifiesto
con la clave de releases usando `minisign`. Los clientes verifican la firma y las
suma de verificación antes de continuar.

## Reversión automática {#automatic-rollback}

Los instaladores conservan la versión previa. Después de actualizar se ejecutan
comprobaciones de disponibilidad (inicio del binario, carga del registro de
plugins y verificación rápida de telemetría). Si alguna falla, la aplicación se
revierte automáticamente, se restablece el canal a estable y se informa al
usuario.

Los clientes también permiten la reversión manual: la UI del escritorio ofrece un
botón "Restaurar versión anterior" y `glyphctl self-update` acepta `--rollback`.

## Lista de verificación para releases {#release-engineering}

Suma estos pasos al proceso habitual:

1. Completa los archivos JSON en `packaging/updater/` con los artefactos del
   release. Consulta `packaging/updater/README.md` para ver el esquema.
2. Exporta la clave privada ed25519 en base64 mediante la variable de entorno
   `0XGEN_UPDATER_SIGNING_KEY`.
3. Ejecuta `make updater:build-manifests` para crear y firmar los manifiestos.
4. Revisa `out/updater/` y confirma que existan los deltas esperados o que el
   manifiesto marque la ausencia correctamente.
5. Publica artefactos y manifiestos en la CDN.
6. Realiza pruebas de humo en macOS, Windows y Linux con el canal beta antes de
   promover a estable.
7. Archiva la telemetría de la actualización para facilitar el análisis de
   reversiones.
