# Learn mode

Learn mode layers contextual guidance on top of the documentation so new
operators can follow complex workflows without switching tabs. When enabled, the
site highlights any element annotated with `data-learn-label` and shows an AI
prompt describing the step. The prompts are currently authored by the docs team
and will be generated dynamically once the Mimir assistant is integrated.

## Enabling Learn mode

- Click the **Learn mode** toggle in the lower-right corner of any page.
- Alternatively append `?learn=1` to the URL to auto-enable the overlay when
  deep-linking into tutorials.
- The preference persists via `localStorage`, so the overlay will remain active
  as you navigate between pages until you turn it off.

## What to expect

When Learn mode is active:

- Steps marked with `.learn-step` receive numbered badges and animated outlines.
- A floating panel surfaces the associated guidance, tips, or follow-up actions.
- Media elements (images, videos, sandboxes) expose play buttons so you can
  trigger walkthroughs without scrolling.

The Quickstart tutorial and the plugin SDK guides already ship with annotations
covering every major action. Additional pages will gain overlays as we expand
coverage.

## Future Mimir integration

Upcoming releases will stream contextual hints from the Mimir runtime. When that
lands, each highlighted step will include a "Ask Mimir" button that replays the
exact CLI commands or API calls for your environment. Until then, Learn mode is
purely client-side and safe to use offline.
