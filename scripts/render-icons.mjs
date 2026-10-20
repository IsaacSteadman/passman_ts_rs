// Renders frontend/icons/shield_lock.svg to the PNG sizes the web app
// manifest and iOS need. The PNGs are committed; rerun this after changing the
// SVG: `node scripts/render-icons.mjs`
import { chromium } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const iconsDir = join(
  dirname(fileURLToPath(import.meta.url)),
  "../frontend/icons",
);
// The SVG's text asks for the generic `sans-serif`, which a minimal font setup
// may map to a serif font; name a sans font so the PNGs come out the same.
const svg = (
  await readFile(join(iconsDir, "shield_lock.svg"), "utf8")
).replaceAll(
  "font-family:sans-serif",
  "font-family:'DejaVu Sans',Arial,Helvetica,sans-serif",
);
const svgUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}`;

// `scale` is the icon's share of the image width. Maskable icons may be cropped
// to a circle of 80% of the width, and iOS rounds the corners of touch icons,
// so those get a background and a smaller icon.
const outputs = [
  { file: "icon-32.png", size: 32, scale: 1, background: null },
  { file: "icon-192.png", size: 192, scale: 1, background: null },
  { file: "icon-512.png", size: 512, scale: 1, background: null },
  {
    file: "icon-maskable-512.png",
    size: 512,
    scale: 0.7,
    background: "#ffffff",
  },
  {
    file: "apple-touch-icon.png",
    size: 180,
    scale: 0.84,
    background: "#ffffff",
  },
];

const browser = await chromium.launch();
try {
  for (const { file, size, scale, background } of outputs) {
    const page = await browser.newPage({
      viewport: { width: size, height: size },
    });
    const iconSize = Math.round(size * scale);
    await page.setContent(`<!doctype html>
      <body style="margin:0;width:${size}px;height:${size}px;display:flex;align-items:center;justify-content:center;background:${background ?? "transparent"}">
        <img src="${svgUrl}" width="${iconSize}" height="${iconSize}">
      </body>`);
    await page.locator("img").evaluate((img) => img.decode());
    await page.screenshot({
      path: join(iconsDir, file),
      omitBackground: background == null,
    });
    await page.close();
  }
} finally {
  await browser.close();
}
