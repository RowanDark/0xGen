# Versiones de la documentación

Glyph publica instantáneas de la documentación para cada versión estable. Así
puedes seguir una API o CLI concreta aunque aparezcan lanzamientos más nuevos.

## Consulta qué ha cambiado

Visita la [vista de comparación](compare.md) para generar un diff entre dos
versiones publicadas. El asistente precarga la vista de comparación de GitHub y
ofrece accesos rápidos a las notas de lanzamiento y al changelog
correspondientes.

## Seleccionar una versión

Utiliza el menú **Version** en la cabecera del sitio para cambiar entre la
versión publicada y los archivos históricos. Cada opción apunta a la raíz de la
instantánea para que la navegación relativa permanezca en la versión elegida.

!!! tip "Enlazar a una versión concreta"
    Usa las direcciones bajo `/versions/<id>/` cuando compartas documentación
    de un lanzamiento anterior. Esos enlaces seguirán funcionando aunque se
    publique una actualización posterior.

## Crear una nueva instantánea

Al preparar un lanzamiento, captura la documentación en `docs/en/versions/`
ejecutando:

```bash
python scripts/snapshot_docs.py vX.Y.Z --latest
```

El script auxiliar:

- copia la documentación en inglés en `docs/en/versions/vX.Y.Z/`,
- actualiza todos los manifiestos `doc-versions.json` para mantener el selector
  sincronizado tanto en el sitio actual como en los archivos, y
- conserva las entradas antiguas eliminando sufijos "(Latest)" obsoletos.

Si necesitas regenerar una instantánea existente (por ejemplo para corregir un
error), añade `--force` para sobrescribir el directorio de destino.

## Instantáneas disponibles

Por ahora los archivos versionados se publican únicamente en inglés:

- [Documentación más reciente](../../)
- [v2.0](../../versions/v2.0/)
- [v1.0](../../versions/v1.0/)
