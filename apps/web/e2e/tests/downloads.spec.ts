import { expect, test } from '@playwright/test';

import { recordedRequests, signIn } from './helpers';

const CLEAN_QUARANTINED = 'a7f00000-0000-4000-8000-000000000001';
const MALICIOUS = 'a7f00000-0000-4000-8000-000000000002';

test.describe('download manager', () => {
  test('lists artifacts with their three independent security statuses', async ({ page }) => {
    await signIn(page, '/downloads?tab=artifacts');
    const statuses = page.getByTestId('artifact-security-status');
    await expect(statuses).toHaveCount(3);
    await expect(page.getByTestId('scan-status').filter({ hasText: 'Malicious' })).toBeVisible();
    await expect(
      page.getByTestId('lifecycle-status').filter({ hasText: 'Quarantined' }),
    ).toHaveCount(2);
  });

  test('releases a clean quarantined artifact only after confirmation with a reason', async ({
    page,
  }) => {
    await signIn(page, `/downloads/artifacts/${CLEAN_QUARANTINED}`);
    await expect(page.getByTestId('lifecycle-status').first()).toHaveText('Quarantined');
    await expect(page.getByRole('button', { name: 'Download unavailable' })).toBeDisabled();

    await page.getByRole('button', { name: 'Release' }).click();
    const dialog = page.getByRole('alertdialog');
    await expect(dialog).toContainText('Release is not verification');
    const confirm = dialog.getByRole('button', { name: 'Release' });
    await expect(confirm).toBeDisabled();
    await dialog.getByLabel(/Reason/).fill('Reviewed in the isolated lab');
    await confirm.click();

    await expect(dialog).toBeHidden();
    await expect(page.getByTestId('lifecycle-status').first()).toHaveText('Released');
    await expect(page.getByText('Reviewed in the isolated lab')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download file' })).toBeEnabled();

    const change = (await recordedRequests()).find(
      (entry) => entry.method === 'POST' && entry.path.endsWith('/lifecycle'),
    );
    expect(change?.headers['if-match']).toBe('"1"');
    expect(change?.body).toEqual({ status: 'released', reason: 'Reviewed in the isolated lab' });
  });

  test('does not offer release for a malicious artifact', async ({ page }) => {
    await signIn(page, `/downloads/artifacts/${MALICIOUS}`);
    await expect(page.getByTestId('scan-status').first()).toHaveText('Malicious');
    await expect(page.getByRole('button', { name: 'Release' })).toBeDisabled();
    await expect(page.getByText(/Release requires a clean scan/)).toBeVisible();
    await expect(page.getByText('Eicar-Test-Signature').first()).toBeVisible();
  });
});
