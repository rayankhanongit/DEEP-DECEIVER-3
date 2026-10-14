# Frontend redesign - design notes

Reference: dark "cube wave" interface (near-black, lavender light, one large
visual, quiet panels). The reference was used for its visual language, not
copied.

## What was extracted from the reference

| Aspect | Decision |
|---|---|
| Background | Void-black with a violet tint (`#09080f`), two soft radial lights, no flat black |
| Accent | One lavender-violet (`#a78bfa`); the previous cyan was removed |
| Surfaces | Dark translucent panels, 1px violet-tinted borders, restrained blur |
| Light | Single source from above; shadows tinted violet |
| Visual | Instanced cube wave, lavender peaks to charcoal troughs, bright travelling light |
| Type | Geist (variable, self-hosted) + Geist Mono; tabular numbers for data |
| Shape | Tighter radii inside (6-10px), softer outside (16-22px) |
| Motion | Ambient wave only; everything else is 140-240ms transform/opacity |

## System

* Tokens: `src/styles/tokens.css`; base: `base.css`; primitives: `ui.css`;
  screens: `app.css`; refinements from the guideline audit: `polish.css`.
* Components: `src/components/ui/` - Button, Badge / StatusBadge /
  SeverityBadge, Dialog (focus trap), Card, MetricCard, RiskMeter, CountUp,
  EmptyState, Spinner, `status.js` (state mapping).
* Security states always carry icon + text + colour: Safe, Blocked attempt,
  Warning, Critical, Successful jailbreak.
* Cube wave (`CubeWave.jsx`): one `InstancedMesh` (15x15), on-demand frames at
  ~30 fps, paused when hidden / off-screen, still frame under
  `prefers-reduced-motion`, CSS fallback without WebGL, lazy-loaded.
* Operator-only screens (Security Monitor, SOC, Red Team) are code-split.

## Unchanged by design

Backend, API contracts, polling / stop / reset logic of the Red Team panel,
SSE alerts, operator unlock (Ctrl+Shift+O), and the stealth behaviour: an
ordinary visitor still sees a plain chat with no security UI.
