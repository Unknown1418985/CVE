import { expect, test } from '@playwright/test';

import { resetMock } from './helpers';

test.describe('authentication', () => {
  test('redirects to Keycloak, returns to the requested page and signs out', async ({
    page,
    context,
  }) => {
    await resetMock();
    await page.goto('/cves?severity=critical');

    await expect(page).toHaveURL(/\/cves\?severity=critical$/);
    await expect(page.getByTestId('user-menu')).toContainText('Avery Admin');

    // Tokens stay on the server: the only session cookie is httpOnly and opaque.
    const cookies = await context.cookies();
    const session = cookies.find((cookie) => cookie.name === 'cve_session');
    expect(session?.httpOnly).toBe(true);
    expect(session?.value).not.toContain('eyJ');
    expect(await page.evaluate(() => document.cookie)).not.toContain('cve_session');

    await page.getByTestId('user-menu').click();
    await page.getByRole('menuitem', { name: 'Sign out' }).click();
    await expect(page).toHaveURL(/\/signed-out$/);
    expect(
      (await context.cookies()).find((cookie) => cookie.name === 'cve_session')?.value ?? '',
    ).toBe('');
  });

  test('refuses a cross-site API mutation', async ({ page, request }) => {
    await resetMock();
    await page.goto('/');
    await expect(page.getByTestId('user-menu')).toBeVisible();
    const cookies = await page.context().cookies();
    const response = await request.post(
      '/bff/api/v1/download-artifacts/a7f00000-0000-4000-8000-000000000001/lifecycle',
      {
        headers: {
          origin: 'https://evil.example',
          cookie: cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join('; '),
          'content-type': 'application/json',
        },
        data: { status: 'released', reason: 'csrf' },
      },
    );
    expect(response.status()).toBe(403);
  });
});
