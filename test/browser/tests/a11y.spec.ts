import { test, expect, Page } from '@playwright/test';

test.setTimeout(60_000);

/**
 * WCAG 2.2 AA checks against the rendered widget.
 *
 * Computed from what the browser actually paints rather than from the source
 * colours, because the widget is injected into someone else's page and the value
 * that matters is the one after cascade. The palette failed on seven counts
 * before this suite existed — including the checkbox border at 1.72:1, the
 * visual boundary of the control itself.
 */

const relLum = (rgb: [number, number, number]) => {
  const [r, g, b] = rgb.map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

const contrast = (a: [number, number, number], b: [number, number, number]) => {
  const la = relLum(a), lb = relLum(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
};

const parse = (css: string): [number, number, number] => {
  const m = css.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
  if (!m) throw new Error(`cannot parse colour: ${css}`);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
};

async function render(page: Page, theme: 'light' | 'dark') {
  await page.route('http://localhost:3000/__a11y__', (r) =>
    r.fulfill({
      status: 200,
      contentType: 'text/html; charset=utf-8',
      body: `<!doctype html><html lang="en"><body style="background:#fff">
        <div id="c"></div>
        <script src="http://localhost:3000/fcaptcha.js"></script>
        <script>FCaptcha.configure({serverUrl:'http://localhost:3000'});
                FCaptcha.render('c',{siteKey:'a11y',theme:'${theme}'});</script>
      </body></html>`,
    })
  );
  await page.goto('http://localhost:3000/__a11y__');
  await page.waitForSelector('.fcaptcha-label');
}

/** Colour of an element, resolving `transparent` up to its painted ancestor. */
async function paintedBg(page: Page, selector: string) {
  return page.$eval(selector, (el) => {
    let node: HTMLElement | null = el as HTMLElement;
    while (node) {
      const bg = getComputedStyle(node).backgroundColor;
      if (bg && !/rgba\(0,\s*0,\s*0,\s*0\)|transparent/.test(bg)) return bg;
      node = node.parentElement;
    }
    return 'rgb(255, 255, 255)';
  });
}

for (const theme of ['light', 'dark'] as const) {
  test(`SC 1.4.3 text contrast >= 4.5:1 (${theme})`, async ({ page }) => {
    await render(page, theme);
    const surface = parse(await paintedBg(page, '.fcaptcha-widget'));

    for (const sel of ['.fcaptcha-label', '.fcaptcha-brand', '.fcaptcha-logo']) {
      const fg = parse(await page.$eval(sel, (el) => getComputedStyle(el).color));
      const ratio = contrast(fg, surface);
      expect(ratio, `${sel} in ${theme} theme`).toBeGreaterThanOrEqual(4.5);
    }
  });

  test(`SC 1.4.11 the control boundary is >= 3:1 (${theme})`, async ({ page }) => {
    await render(page, theme);
    const surface = parse(await paintedBg(page, '.fcaptcha-widget'));
    const border = parse(
      await page.$eval('.fcaptcha-checkbox', (el) => getComputedStyle(el).borderTopColor)
    );
    // The edge a person has to find in order to click it.
    expect(contrast(border, surface), `checkbox border in ${theme}`).toBeGreaterThanOrEqual(3);
  });
}

test('SC 2.5.8 the target is at least 24x24 CSS px', async ({ page }) => {
  await render(page, 'light');
  const box = await page.locator('.fcaptcha-checkbox').boundingBox();
  expect(box!.width).toBeGreaterThanOrEqual(24);
  expect(box!.height).toBeGreaterThanOrEqual(24);
});

test('SC 2.4.7 focus is visible, and survives a hostile host stylesheet', async ({ page }) => {
  await render(page, 'light');
  // A host page suppressing outlines globally is common and would otherwise
  // leave a keyboard user with nothing to see.
  await page.addStyleTag({ content: '*:focus { outline: none !important; }' });
  await page.locator('.fcaptcha-checkbox').focus();

  const style = await page.$eval('.fcaptcha-checkbox', (el) => {
    const s = getComputedStyle(el);
    return { outlineWidth: s.outlineWidth, outlineStyle: s.outlineStyle, boxShadow: s.boxShadow };
  });
  const hasIndicator =
    (style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0) ||
    (style.boxShadow && style.boxShadow !== 'none');
  expect(hasIndicator, `no visible focus indicator: ${JSON.stringify(style)}`).toBeTruthy();
});

test('SC 2.1.1 the control is operable by keyboard', async ({ page }) => {
  await render(page, 'light');
  await page.keyboard.press('Tab');
  const focused = await page.evaluate(() => document.activeElement?.className || '');
  expect(focused).toContain('fcaptcha-checkbox');
});

test('SC 1.4.1 state is not conveyed by colour alone', async ({ page }) => {
  await render(page, 'light');
  // The label carries the state in words; the glyph and fill are reinforcement.
  const label = await page.locator('.fcaptcha-label').innerText();
  expect(label.trim().length).toBeGreaterThan(0);
  await expect(page.locator('.fcaptcha-label')).toHaveAttribute('aria-live', 'polite');
});

test('decorative glyphs are hidden from assistive technology', async ({ page }) => {
  await render(page, 'light');
  for (const sel of ['.fcaptcha-spinner', '.fcaptcha-checkmark', '.fcaptcha-x']) {
    await expect(page.locator(sel)).toHaveAttribute('aria-hidden', 'true');
  }
});

test('the spinner stops under prefers-reduced-motion', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await render(page, 'light');
  const animation = await page.$eval(
    '.fcaptcha-spinner',
    (el) => getComputedStyle(el).animationName
  );
  expect(animation).toBe('none');
});

test('SC 1.4.10 the widget fits a 320px viewport without horizontal scroll', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 600 });
  await render(page, 'light');
  const overflows = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth
  );
  expect(overflows, 'widget forces horizontal scrolling at 320px').toBeFalsy();
});
