import { expect, test } from '@playwright/test';

import { signIn } from './helpers';

test.describe('CVE intelligence', () => {
  test('filters by severity and paginates real API results', async ({ page }) => {
    await signIn(page, '/cves');
    const table = page.getByRole('table', { name: 'CVE records' });
    await expect(table.getByRole('link', { name: 'CVE-2026-90030' })).toBeVisible();
    await expect(page.getByText('Page 1 of 2')).toBeVisible();

    await page.getByRole('button', { name: 'Next page' }).click();
    await expect(page).toHaveURL(/page=2/);
    await expect(table.getByRole('link', { name: 'CVE-2026-90001' })).toBeVisible();

    await page.getByRole('button', { name: /^Severity:/ }).click();
    await page.getByRole('menuitemcheckbox', { name: 'Critical' }).click();
    await page.keyboard.press('Escape');
    await expect(page).toHaveURL(/severity=critical/);
    await expect(page).not.toHaveURL(/page=2/);
    await expect(page.getByText('Page 1 of 1')).toBeVisible();
    const rows = table.locator('tbody tr');
    await expect(rows).toHaveCount(5);
    await expect(table.getByTestId('severity-badge').first()).toContainText('Critical');
  });

  test('shows an empty state when nothing matches', async ({ page }) => {
    await signIn(page, '/cves?q=no-such-record');
    await expect(page.getByText('No CVE records match')).toBeVisible();
  });

  test('opens a CVE from global search and shows its details', async ({ page }) => {
    await signIn(page, '/');
    await page.keyboard.press('ControlOrMeta+k');
    await page
      .getByPlaceholder('CVE-2026-1234, vendor, product, repository…')
      .fill('CVE-2026-90010');
    await expect(page.getByRole('option', { name: /Open CVE-2026-90010/ })).toBeVisible();
    await page.keyboard.press('Enter');
    await expect(page).toHaveURL(/\/cves\/CVE-2026-90010$/);
    await expect(page.getByRole('heading', { level: 1 })).toContainText('CVE-2026-90010');
    await expect(page.getByTestId('kev-badge').first()).toBeVisible();
    await expect(
      page.getByText('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').first(),
    ).toBeVisible();
  });

  test('shows an error state with the correlation ID when the service fails', async ({ page }) => {
    await signIn(page, '/cves', { fail: ['cves'] });
    await expect(page.getByRole('alert').filter({ hasText: 'The service failed' })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.getByText(/e2e-[0-9a-f-]{36}/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
  });
});
