# Redesign v2 - extraction and decisions

The first redesign pasted a cube component into the old layout. v2 rebuilds the
product around the reference's visual language.

## Why v1 failed (measured with Playwright on the running app)

* 520 of ~530 text elements were 12-14 px; the hero was 52 px.
* The cube field was a small static tile in the upper middle, not the stage.
* A permanent 272 px sidebar took 19 % of the viewport.
* The dashboard was a grid of boxed cards; everything was a container.

## Extraction from the reference (image-to-code, analysis step)

The image-generation step of the skill could not be run (no generator is
available here), so the supplied reference was analysed directly:

| Observation | Decision |
|---|---|
| The cube field fills the frame and emerges from black; no frame or border | One full-screen `Stage` behind the whole app, masked and veiled into the background |
| Elevated three-quarter camera, visible cube sides, charcoal valleys between lavender peaks | Camera at ~25 deg, wave amplitude 0.3-2.0, `LOW #241f38` to `HIGH #9378ea` |
| A single bright pool of light | One moving point light that follows the cursor |
| Almost no UI chrome, big whitespace | Hidden nav, one headline, one composer, three text prompts; no pills on the hero |
| Near-black with a violet cast | `--bg #07060d`; all neutrals share the violet hue |

## System

* Tokens (`styles/tokens.css`): type scale (15 / 17 / 20 / 24 / 28-36 / 44-88 /
  44-64 px), 4 px spacing scale, radii, shadows, motion and a z-index scale.
  Nothing important is below 15 px.
* Hero: one 1-2 line headline, one sentence, composer, three prompts.
* Composer: 20 px text, 32 px radius, lavender focus glow, 56 px send button.
* Dashboard: one verdict surface (risk meter, plain-language verdict, three
  large numbers), then open sections separated by hairlines, not nested cards.
* Red Team: right-hand sheet instead of a modal (progress, risk, findings).
* Status: icon + word + colour; findings and events also carry a left-edge cue.

## Interaction

* **Cursor-reactive cubes** (`CubeWave.jsx`): pointer -> ray -> floor plane ->
  grid cell. Every cube is a damped spring pulled toward a Gaussian around the
  cursor *and* coupled to its four neighbours (discrete wave equation), so
  movement injects energy that ripples outward and settles by itself.
  Touch uses the same pointer events. Reduced motion draws one still frame and
  disables the effect; a header button pauses the animation for everyone.
* **Auto-hiding sidebar** (`App.jsx`): off-canvas by default, a lavender seam
  marks the left edge. Entering the edge zone opens it as an overlay (the page
  is not resized); leaving closes it after 520 ms; re-entering cancels the
  close. The nav button, `aria-expanded`, Escape and focus return provide the
  keyboard path; the closed panel is `inert`. On small screens it is a drawer
  with a scrim.
