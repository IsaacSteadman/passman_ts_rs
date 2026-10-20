import { test, expect } from "@playwright/test";

test.describe("Installable app", () => {
  test("Chromium finds the manifest and can install the app", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    const cdp = await page.context().newCDPSession(page);

    const { url, errors, data } = await cdp.send("Page.getAppManifest");
    expect(url).toMatch(/\/manifest\.webmanifest$/);
    expect(errors).toEqual([]);
    const manifest = JSON.parse(data ?? "{}") as {
      display?: string;
      icons?: { src: string; sizes: string; purpose?: string }[];
    };
    expect(manifest.display).toBe("standalone");

    // every icon the manifest lists can be downloaded
    for (const icon of manifest.icons ?? []) {
      const response = await page.request.get(icon.src);
      expect(response.ok(), icon.src).toBe(true);
      expect(response.headers()["content-type"]).toBe("image/png");
    }

    const { installabilityErrors } = await cdp.send(
      "Page.getInstallabilityErrors",
    );
    expect(installabilityErrors).toEqual([]);
  });

  test("iOS home screen icon is linked", async ({ page }) => {
    await page.goto("/");
    const href = await page
      .locator("link[rel='apple-touch-icon']")
      .getAttribute("href");
    const response = await page.request.get(href!);
    expect(response.ok()).toBe(true);
  });
});
