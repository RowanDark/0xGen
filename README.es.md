# 0xgen

[![Estado de la documentación](https://github.com/RowanDark/0xgen/actions/workflows/docs.yml/badge.svg?branch=main)](https://rowandark.github.io/0xgen/)

0xgen es un conjunto de herramientas de automatización para orquestar flujos de trabajo de red teaming y detección. Coordina complementos como Galdr (proxy de reescritura HTTP), Excavator (rastreador Playwright), Seer (detector de secretos/PII), Ranker y Scribe para convertir telemetría sin procesar en hallazgos priorizados e informes legibles para humanos.

## Instalación

### macOS (Homebrew)

Las personas usuarias de macOS pueden instalar el binario precompilado `0xgenctl` mediante Homebrew utilizando el [tap RowanDark/homebrew-0xgen](https://github.com/RowanDark/homebrew-0xgen):

```bash
brew install rowandark/0xgen/0xgen
```

### Linux (Debian/Ubuntu)

Descarga el paquete `.deb` desde la [página de lanzamientos en GitHub](https://github.com/RowanDark/0xgen/releases) e instálalo con `dpkg`:

```bash
sudo dpkg -i 0xgenctl_<version>_linux_amd64.deb
```

Sustituye `<version>` por la versión que deseas instalar. El paquete instala `0xgenctl` en `/usr/local/0xgen/bin`. Añade ese directorio a tu `PATH` o crea un enlace simbólico si prefieres invocar la CLI sin ruta completa.

### Linux (Fedora/RHEL/OpenSUSE)

Los paquetes RPM se publican junto con cada lanzamiento. Instálalos con `rpm`:

```bash
sudo rpm -i 0xgenctl_<version>_linux_amd64.rpm
```

### Windows

Hay tres métodos de instalación compatibles en Windows:

#### Instalador (MSI)

Descarga el artefacto `0xgenctl_v<version>_windows_amd64.msi` (o `arm64`) desde la [página de lanzamientos](https://github.com/RowanDark/0xgen/releases). Ábrelo con doble clic o desde PowerShell:

```powershell
msiexec /i .\0xgenctl_v<version>_windows_amd64.msi /qn
```

El instalador coloca `0xgenctl.exe` en `C:\Program Files\0xgen` y actualiza `PATH` para sesiones futuras. Verifica la instalación:

```powershell
"C:\Program Files\0xgen\0xgenctl.exe" --version
```

#### ZIP portable

Cada lanzamiento incluye un archivo portátil llamado `0xgenctl_v<version>_windows_<arch>.zip`. Extráelo donde prefieras y ejecuta el binario incluido:

```powershell
Expand-Archive -Path .\0xgenctl_v<version>_windows_amd64.zip -DestinationPath C:\Tools\0xgen
C:\Tools\0xgen\0xgenctl.exe --version
```

#### Scoop

Agrega este repositorio como un bucket de Scoop e instala el manifiesto publicado:

```powershell
scoop bucket add 0xgen https://github.com/RowanDark/0xgen
scoop install 0xgenctl
0xgenctl --version
```

### Imagen de contenedor

Se publica una imagen de contenedor reforzada en GitHub Container Registry con cada lanzamiento. La imagen se ejecuta como una persona usuaria sin privilegios y espera un sistema de archivos raíz de solo lectura. Descárgala y ejecuta `0xgenctl` con el perfil de privilegios mínimos recomendado:

```bash
docker pull ghcr.io/rowandark/0xgenctl:latest
docker run \
  --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt no-new-privileges \
  --pids-limit=256 \
  --memory=512m \
  --cpus="1.0" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --tmpfs /home/nonroot/.cache:rw,noexec,nosuid,nodev,size=64m \
  --mount type=volume,source=oxg-data,dst=/home/nonroot/.oxg \
  --mount type=volume,source=oxg-output,dst=/out \
  ghcr.io/rowandark/0xgenctl:latest --version
```

Consulta la [guía de endurecimiento de contenedores](docs/en/security/container.md) para obtener contexto adicional, notas de integración en CI y consejos sobre la ejecución de complementos.

## Inicio rápido

Clona el repositorio y ejecuta la canalización de demostración sin interacción:

```bash
0xgenctl demo
```

El comando levanta un objetivo de demostración local, ejecuta el detector Seer, clasifica los hallazgos generados y emite un informe HTML interactivo en `out/demo/`. `make demo` sigue disponible como una capa delgada si prefieres un punto de entrada basado en Make. Consulta el [recorrido de Inicio rápido](https://rowandark.github.io/0xgen/quickstart/) para ver una guía completa y notas de solución de problemas.

## Documentación

Explora el sitio de documentación completo en [rowandark.github.io/0xgen](https://rowandark.github.io/0xgen/). Destacados:

* [Demostración de inicio rápido](https://rowandark.github.io/0xgen/quickstart/)
* [Guía para autores de complementos](https://rowandark.github.io/0xgen/plugins/)
* [Referencia de la CLI](https://rowandark.github.io/0xgen/cli/)
* [Guía de desarrollo](https://rowandark.github.io/0xgen/dev-guide/)
* [Resumen de seguridad](https://rowandark.github.io/0xgen/security/)
* [Procedencia de compilaciones](https://rowandark.github.io/0xgen/security/provenance/)
* [Seguridad de la cadena de suministro](https://rowandark.github.io/0xgen/security/supply-chain/)
* [Modelo de amenazas](https://rowandark.github.io/0xgen/security/threat-model/)
* [Guía de seguridad para complementos](PLUGIN_GUIDE.md)

## Seguridad

Revisa nuestra [política de seguridad](SECURITY.md) para obtener instrucciones sobre cómo reportar vulnerabilidades, versiones compatibles y la cronograma de divulgación. El [modelo de amenazas de 0xgen](THREAT_MODEL.md) describe los vectores de ataque principales y las suposiciones, mientras que la [guía de seguridad de complementos](PLUGIN_GUIDE.md) resume los patrones seguros para nuevas integraciones.
