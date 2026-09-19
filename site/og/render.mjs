// Regenerates public/og.png (1200x630) from og/og.html with the locally cached Playwright Chromium.
// Usage: pnpm og   (needs network for Google Fonts; set CHROMIUM_PATH to override the browser)
import { chromium } from "playwright-core";
import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "public", "og.png");

function findChromium() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;
  const cache = process.platform === "darwin" ? join(homedir(), "Library/Caches/ms-playwright") : join(homedir(), ".cache/ms-playwright");
  const candidates = [];
  for (const dir of existsSync(cache) ? readdirSync(cache) : []) {
    const base = join(cache, dir);
    const tries = dir.startsWith("chromium_headless_shell-")
      ? ["chrome-headless-shell-mac-arm64/chrome-headless-shell", "chrome-headless-shell-mac-x64/chrome-headless-shell", "chrome-headless-shell-linux64/chrome-headless-shell"]
      : dir.startsWith("chromium-")
        ? ["chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium", "chrome-mac/Chromium.app/Contents/MacOS/Chromium", "chrome-linux/chrome"]
        : [];
    for (const t of tries) if (existsSync(join(base, t))) candidates.push(join(base, t));
  }
  candidates.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  if (!candidates.length) throw new Error("No cached Playwright Chromium found. Set CHROMIUM_PATH or run `npx playwright install chromium`.");
  return candidates[0];
}

const browser = await chromium.launch({ executablePath: findChromium() });
try {
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(join(here, "og.html")).href, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  const loaded = await page.evaluate(() =>
    ['700 57px "Bricolage Grotesque"', '400 23px "Onest"', '400 21px "Geist Mono"'].every((f) => document.fonts.check(f)),
  );
  if (!loaded) throw new Error("Web fonts did not load (offline?). Refusing to render with fallback fonts.");
  await page.screenshot({ path: out, clip: { x: 0, y: 0, width: 1200, height: 630 } });
  console.log("wrote", out);
} finally {
  await browser.close();
}
