# Accessibility

FCaptcha is intended to let people complete protected actions without solving a
visual or audio puzzle. Accessibility is part of the security model: a detector
that mistakes keyboard, assistive-technology, touch, tremor, slow, or
high-latency interaction for automation is defective even if it catches bots.

## Scope and target

The shipped checkbox widget is designed and tested against the applicable WCAG
2.2 Level AA success criteria exercised by this repository. This is a project
target backed by automated checks, not a claim of formal third-party
certification or a guarantee that every host-page integration is conformant.

The widget provides:

- has an accessible name, checkbox role, and programmatic checked state;
- is reachable and operable with a keyboard using Space or Enter;
- announces verifying, verified, and failed states through a polite live region;
- does not rely on colour alone and hides decorative glyphs from assistive
  technology;
- preserves visible focus even when a host stylesheet globally suppresses
  outlines, while retaining an outline for forced-colours modes;
- meets the tested text and non-text contrast thresholds in light and dark
  themes;
- provides at least a 24 by 24 CSS-pixel target;
- fits a 320 CSS-pixel viewport without horizontal scrolling;
- disables spinner animation and control transitions when reduced motion is
  requested; and
- applies localized text and right-to-left layout for supported RTL languages.

The browser suite verifies the rendered control's accessible name, keyboard
focusability, live-region semantics, decorative-element hiding, contrast,
target size, focus visibility, reduced-motion behavior, 320 CSS-pixel reflow,
localization, and RTL direction. Keyboard activation and checked-state updates
are implemented by the same widget code but should also be covered by future
browser assertions.

The invisible API has no interactive CAPTCHA control. Integrators remain
responsible for the accessibility of the surrounding form, its instructions,
validation, error handling, and success messages. Example applications and
third-party framework wrappers are not covered by the widget's test scope unless
their own documentation says otherwise.

## False-positive protections

Accessibility is also tested below the interface layer. The benchmark corpus
contains keyboard-only, screen-reader, touch, motor-tremor, elderly,
motor-slow, and high-latency personas. CI fails when an individual detection
signal exceeds its false-positive budget on the committed human panel.

Those results are regression evidence, not a population estimate. Most scripted
personas come from one machine, parts of their browser environment are
normalized, and automated checks do not replace testing with disabled people
using their own browsers, devices, and assistive technology. The limitations and
provenance rules are documented in [the benchmark README](bench/README.md).

## Contributor expectations

Changes to the widget or scoring logic must not make a protected action depend
on pointer movement, speed, visual perception, hearing, or an interaction style
that a legitimate visitor may not produce. Existing keyboard and touch
exemptions are load-bearing security behavior, not optional tuning.

For user-facing changes:

1. Preserve native or equivalent keyboard operation, accessible names, state,
   focus indication, reduced-motion behavior, reflow, and contrast.
2. Run the browser suite in `test/browser`; its accessibility checks live in
   `test/browser/tests/a11y.spec.ts`.
3. Run the benchmark gate for changes that affect signals or scoring, and
   compare every human persona rather than only the aggregate score.
4. Document the browsers, operating systems, input devices, and assistive
   technology used for any manual evaluation. A recording or disability
   disclosure is never required.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the complete test workflow.

## Reporting an accessibility barrier

Open a [bug report](https://github.com/WebDecoy/FCaptcha/issues/new?template=bug.yml)
for an interface, documentation, or integration barrier. If a legitimate
visitor was scored as a bot, use the dedicated
[false-positive report](https://github.com/WebDecoy/FCaptcha/issues/new?template=false-positive.yml).

Please include, when you are comfortable doing so:

- the task you were trying to complete;
- what you expected and what happened instead;
- the FCaptcha version and server implementation;
- browser, operating system, input device, and relevant assistive technology;
- a minimal reproduction or affected URL; and
- whether a workaround exists.

Screenshots, recordings, and personal or medical information are optional. Do
not include secrets, tokens, raw visitor telemetry, or other people's personal
data. Report security vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

Maintainers triage accessibility reports by how strongly the barrier prevents a
person from completing the protected task, whether a workaround exists, and how
broadly the affected interaction is used. Reporters do not need to choose a
severity level.
