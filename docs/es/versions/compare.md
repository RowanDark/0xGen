---
title: Comparar versiones de la documentación
---

# Comparar versiones de la documentación

Usa el selector para precargar un diff en GitHub entre dos versiones. Una vez
abierta la vista de comparación, utiliza el campo **Filter changed files** de
GitHub para escribir `docs/` y centrarte en los cambios de documentación. El
asistente también ofrece enlaces rápidos a las notas de lanzamiento y al
changelog del proyecto.

<div data-version-diff class="doc-version-diff">
  <noscript>
    <p><strong>Se requiere JavaScript:</strong> habilita JavaScript para generar el
    diff. Como alternativa abre el <a href="https://github.com/RowanDark/0xgen/blob/main/CHANGELOG.md" target="_blank" rel="noopener">changelog</a> o usa
    manualmente la herramienta de comparación de GitHub:</p>
    <ol>
      <li>Visita <a href="https://github.com/RowanDark/0xgen/compare" target="_blank" rel="noopener">github.com/RowanDark/0xgen/compare</a>.</li>
      <li>Introduce la etiqueta de la versión base (más antigua) y después la etiqueta destino.</li>
      <li>Añade <code>?diff=split</code> a la URL (o usa los controles de la
        interfaz) y escribe <code>docs/</code> en el cuadro <strong>Filter changed
        files</strong> para centrarte en la documentación.</li>
    </ol>
  </noscript>
</div>

## Consejos para compartir diffs

- GitHub guarda las versiones elegidas y cualquier texto del filtro de archivos
  en la URL, lo que facilita compartir un enlace con una comparación concreta.
- Las notas de lanzamiento apuntan a la etiqueta correspondiente de GitHub para
  ver binarios, incidencias y pull requests fusionados en esa versión.
- Las instantáneas de la documentación siguen disponibles bajo `/versions/<id>/`
  si necesitas un enlace estable a una página anterior.
