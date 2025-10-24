# Modos de accesibilidad

0xgen incluye herramientas para simular deficiencias visuales y reducir la luz azul directamente desde la barra superior.

## Simulación de daltonismo

- **Modos disponibles.** Están soportadas las vistas estándar, deuteranopia, protanopia y tritanopia utilizando las mismas transformaciones SVG que las pruebas de regresión.
- **Persistencia.** La preferencia se guarda en `oxg.vision.mode` y se aplica durante el arranque para evitar parpadeos.
- **Refuerzos visuales.** Cuando una simulación está activa, los gráficos de la página de operaciones muestran trazos punteados y marcadores geométricos para no depender solo del color.

## Modo de confort nocturno

- **Control manual o automático.** El selector "Blue light" permite activarlo, desactivarlo o dejarlo en modo automático que se aplica de 19:00 a 06:00.
- **Implementación.** Se usa un filtro sepia con rotación de tono para reducir la energía azul de toda la interfaz y se exponen los estados mediante atributos `data-*`.

## Visualizaciones adaptadas

| Superficie | Comportamiento |
| --- | --- |
| Micrográficos del panel de operaciones | Cambian a patrones de líneas y marcadores con formas distintas cuando hay simulación para mantener la diferenciación. |
