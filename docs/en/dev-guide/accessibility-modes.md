# Accessibility modes

0xgen ships with a11y tooling that mirrors how operators preview the UI in challenging environments. The toggles live in the shell toolbar next to the theme selector so they are reachable with keyboard focus order.

## Color-vision simulation

- **Modes.** You can preview the interface with Deuteranopia, Protanopia, or Tritanopia filters in addition to the standard rendering. The simulation uses the SVG color-matrix transforms from the regression tests so contrast and component affordances stay intact across the app.
- **Persistence.** The chosen simulation is stored in local storage (`oxg.vision.mode`) and re-applied on load, including during the `bootstrapTheme` phase so there is no flash of unsimulated content.
- **Visual cues.** When a simulation is active, sparklines and other data icons render dashed strokes and geometric markers (circle, diamond, square variants) rather than relying only on hue. This keeps hover and legend affordances visible even when colors converge.

## Blue-light comfort mode

- **Manual and scheduled control.** A separate selector enables the warmer “low blue” filter. Choose `On` to lock it in, `Off` to revert, or `Auto (evening)` to let 0xgen enable the tint after 19:00 local time until 06:00 the next day. The current state is exposed via an SR-only description so screen-reader users hear whether the schedule is active.
- **Implementation.** The comfort mode reduces luminance/blue output via a sepia and hue rotation filter that wraps the entire document tree. Dataset flags (`data-blue-light` / `data-blue-light-mode`) allow component-specific overrides if needed.
- **Persistence.** Preferences are stored under `oxg.blue-light.mode` and refreshed every minute while the schedule is enabled.

## Visualisations with shape/pattern fallbacks

| Surface | Behaviour when a simulation is active |
| --- | --- |
| Operations overview stat sparklines | Stroke dashes vary per metric, fills switch to cross-hatch/patterns, and point markers change shape so the trend remains distinguishable without color cues. |

If additional charts are added in the future, favour the same approach: provide at least one redundant channel (shape, pattern, annotation) whenever the rendering relies on a color palette.
