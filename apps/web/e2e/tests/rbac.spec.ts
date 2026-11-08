import { expect, test } from '@playwright/test';

import { signIn } from './helpers';

test.describe('role-based access', () => {
  test('a viewer only sees the sections their role allows', async ({ page }) => {
    await signIn(page, '/', { user: 'viewer' });
    const nav = page.getByRole('navigation', { name: 'Main navigation' }).first();
    await expect(nav.getByRole('link', { name: 'CVE Explorer' })).toBeVisible();
    await expect(nav.getByRole('link', { name: 'Settings' })).toBeVisible();
    for (const hidden of ['User Management', 'Audit Logs', 'Download Manager', 'Data Sources']) {
      await expect(nav.getByRole('link', { name: hidden })).toHaveCount(0);
    }
  });

  test('an administrator sees administration sections', async ({ page }) => {
    await signIn(page, '/', { user: 'admin' });
    const nav = page.getByRole('navigation', { name: 'Main navigation' }).first();
    for (const visible of ['User Management', 'Audit Logs', 'Download Manager', 'Data Sources']) {
      await expect(nav.getByRole('link', { name: visible })).toBeVisible();
    }
  });

  test('a viewer opening a restricted page gets an access message, not data', async ({ page }) => {
    await signIn(page, '/downloads?tab=artifacts', { user: 'viewer' });
    await expect(page.getByText('Access restricted').first()).toBeVisible();
  });
});
