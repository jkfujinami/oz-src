import { test, expect, type Page } from '@playwright/test';

const PASS = 'e2e-passphrase-long';

async function unlock(page: Page) {
  await page.goto('/');
  await page.getByLabel('パスワード', { exact: true }).fill(PASS);
  await page.getByLabel('パスワード (確認)').fill(PASS);
  await page.locator('button[type=submit]').click();
  // 解錠してノードが起動すると、共通ヘッダが出る
  await expect(page.getByText('OZ', { exact: true })).toBeVisible();
}

test('Web: 解錠して、配信元のトラッカーに登録し、2 つのブラウザが WebRTC で繋がる', async ({ browser }) => {
  const errors: string[] = [];
  const a = await (await browser.newContext()).newPage();
  const b = await (await browser.newContext()).newPage();
  for (const p of [a, b]) p.on('pageerror', (e) => errors.push(String(e)));

  await unlock(a);
  await expect(a.getByText('Web', { exact: true })).toBeVisible();
  // 既定のトラッカー (配信元の /ws) が設定されている
  await expect(a.getByRole('button', { name: 'トラッカー', exact: true })).toBeVisible();

  await unlock(b);

  // トラッカーで互いを知り、WebRTC で直接繋がる (PeerManager の JOIN v4 まで通る)
  await expect(a.getByText(/Peers: [1-9]/)).toBeVisible();
  await expect(b.getByText(/Peers: [1-9]/)).toBeVisible();

  expect(errors).toEqual([]);
});

test('Web: 間違ったパスワードでは解錠できない', async ({ browser }) => {
  const page = await (await browser.newContext()).newPage();
  await unlock(page);
  await page.getByRole('button', { name: 'ロック' }).click();
  await page.getByLabel('パスワード', { exact: true }).fill('wrong-passphrase!!');
  await page.locator('button[type=submit]').click();
  await expect(page.getByText('パスワードが違います')).toBeVisible();
});
