# Seguimiento de rebranding: migración de marca (meta)

> **Estado:** Trabajo de preparación

Crear etiqueta: `rebrand`

## Lista de comprobación

- [ ] 1 Renombrar superficies de documentación (solo título/encabezado)
- [ ] 2 Insignias/enlaces del README (sin cambiar URL)
- [ ] 3 Título/icono de la ventana GUI solo texto
- [ ] 4 Banner de la CLI y texto de la salida de `--version`
- [ ] 5 Variables de entorno del directorio de configuración (leer nuevo, retrocompatibilidad con el anterior)
- [ ] 6 Wrapper binario: `0xgenctl` → `0xgenctl` (alias)
- [ ] 7 URLs de la documentación: añadir redirecciones desde el prefijo heredado hacia `/0xgen`
- [ ] 8 Comentario del módulo en `go.mod` solamente (sin cambiar la ruta)
- [ ] 9 Nombre de la fórmula de Homebrew solamente (el alias mantiene glyph)
- [ ] 10 Nombres de trabajos y artefactos en CI (sin cambiar rutas)
- [ ] 11 Final: renombrar repositorio y migrar la ruta del módulo
