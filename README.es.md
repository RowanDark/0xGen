# Glyph

[![Documentación](https://img.shields.io/badge/docs-material-blue)](https://rowandark.github.io/0xgen/)

Glyph es un conjunto de herramientas de automatización para orquestar flujos de trabajo de red teaming y detección. Coordina complementos como Galdr (proxy de reescritura HTTP), Excavator (rastreador Playwright), Seer (detector de secretos/PII), Ranker y Scribe para convertir telemetría sin procesar en hallazgos priorizados e informes legibles para humanos.

## Instalación

### macOS (Homebrew)

Las personas usuarias de macOS pueden instalar el binario precompilado `glyphctl` mediante Homebrew utilizando el [tap RowanDark/homebrew-glyph](https://github.com/RowanDark/homebrew-glyph):

```bash
brew install rowandark/glyph/glyph
# Alias mientras el tap mantiene el nombre de la fórmula Glyph
brew install rowandark/glyph/0xgen
```

### Linux (Debian/Ubuntu)

Descarga el paquete `.deb` desde la [página de lanzamientos en GitHub](https://github.com/RowanDark/0xgen/releases) e instálalo con `dpkg`:

```bash
sudo dpkg -i glyphctl_<version>_linux_amd64.deb
```

Sustituye `<version>` por la versión que deseas instalar. El paquete instala `glyphctl` en `/usr/local/bin`.

### Linux (Fedora/RHEL/OpenSUSE)

Los paquetes RPM se publican junto con cada lanzamiento. Instálalos con `rpm`:

```bash
sudo rpm -i glyphctl_<version>_linux_amd64.rpm
```

### Windows

Hay tres métodos de instalación compatibles en Windows:

#### Instalador (MSI)

Descarga el artefacto `glyphctl_v<version>_windows_amd64.msi` (o `arm64`) desde la [página de lanzamientos](https://github.com/RowanDark/0xgen/releases). Ábrelo con doble clic o desde PowerShell:

```powershell
msiexec /i .\glyphctl_v<version>_windows_amd64.msi /qn
```

El instalador coloca `glyphctl.exe` en `C:\Program Files\Glyph` y actualiza `PATH` para sesiones futuras. Verifica la instalación:

```powershell
"C:\Program Files\Glyph\glyphctl.exe" --version
```

#### ZIP portable

Cada lanzamiento incluye un archivo portátil llamado `glyphctl_v<version>_windows_<arch>.zip`. Extráelo donde prefieras y ejecuta el binario incluido:

```powershell
Expand-Archive -Path .\glyphctl_v<version>_windows_amd64.zip -DestinationPath C:\Tools\Glyph
C:\Tools\Glyph\glyphctl.exe --version
```

#### Scoop

Agrega este repositorio como un bucket de Scoop e instala el manifiesto publicado:

```powershell
scoop bucket add glyph https://github.com/RowanDark/0xgen
scoop install glyphctl
glyphctl --version
```

### Imagen de contenedor

Se publica una imagen de contenedor reforzada en GitHub Container Registry con cada lanzamiento. La imagen se ejecuta como una persona usuaria sin privilegios y espera un sistema de archivos raíz de solo lectura. Descárgala y ejecuta `glyphctl` con el perfil de privilegios mínimos recomendado:

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
  --mount type=volume,source=glyph-data,dst=/home/nonroot/.glyph \
  --mount type=volume,source=glyph-output,dst=/out \
  ghcr.io/rowandark/0xgenctl:latest --version
```

Consulta la [guía de endurecimiento de contenedores](docs/en/security/container.md) para obtener contexto adicional, notas de integración en CI y consejos sobre la ejecución de complementos.

## Inicio rápido

Clona el repositorio y ejecuta la canalización de demostración sin interacción:

```bash
glyphctl demo
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

Revisa nuestra [política de seguridad](SECURITY.md) para obtener instrucciones sobre cómo reportar vulnerabilidades, versiones compatibles y la cronograma de divulgación. El [modelo de amenazas de Glyph](THREAT_MODEL.md) describe los vectores de ataque principales y las suposiciones, mientras que la [guía de seguridad de complementos](PLUGIN_GUIDE.md) resume los patrones seguros para nuevas integraciones.
