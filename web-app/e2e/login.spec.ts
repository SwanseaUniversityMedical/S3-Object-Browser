import { test, expect } from "@playwright/test";
import { adminAccessKey, adminSecretKey, BUCKET_LIST_PAGE } from "./consts";

test("Basic admin login", async ({ page, context }) => {
  await page.goto(BUCKET_LIST_PAGE);
  await page.getByPlaceholder("Username").click();
  await page.getByPlaceholder("Username").fill(adminAccessKey);
  await page.getByPlaceholder("Password").click();
  await page.getByPlaceholder("Password").fill(adminSecretKey);
  await page.getByRole("button", { name: "Login" }).click();
  await context.storageState({ path: "storage/admin.json" });
  await expect(page.getByRole("main").getByText("Object Browser")).toBeTruthy();
});
