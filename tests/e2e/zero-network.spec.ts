import { expect, test } from "@playwright/test";

test("page load and analysis emit no unexpected network requests", async ({
  page,
}) => {
  const requests: string[] = [];
  page.on("request", (request) => {
    requests.push(request.url());
  });

  await page.goto("./");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

  const paste = page.locator("#paste");
  await paste.fill("srcip=10.0.2.15 dstip=192.168.1.10");
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(page.getByRole("cell", { name: "ipv4" }).first()).toBeVisible();
  await expect(page.getByText("Check:")).toBeVisible();

  // After first document load, analysis must not trigger network I/O.
  const initialCount = requests.length;
  expect(initialCount).toBeGreaterThan(0);

  await paste.fill("another=172.16.0.5");
  await page.getByRole("button", { name: "Analyze" }).click();
  await expect(page.getByRole("cell", { name: "ipv4" })).toBeVisible();

  expect(requests.length).toBe(initialCount);

  const external = requests.filter((url) => {
    const parsed = new URL(url);
    return parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost";
  });
  expect(external).toEqual([]);
});
