import { expect, type Page } from '@playwright/test';

export const MOCK_URL = 'http://localhost:4100';

export interface MockOptions {
  readonly user?: 'admin' | 'viewer';
  /** Gateway resources that answer HTTP 500. */
  readonly fail?: readonly string[];
}

export interface RecordedRequest {
  readonly method: string;
  readonly path: string;
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly body: unknown;
}

export async function resetMock(options: MockOptions = {}): Promise<void> {
  const response = await fetch(`${MOCK_URL}/__mock/reset`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(options),
  });
  expect(response.ok).toBe(true);
}

export async function recordedRequests(): Promise<RecordedRequest[]> {
  const response = await fetch(`${MOCK_URL}/__mock/requests`);
  const body = (await response.json()) as { requests: RecordedRequest[] };
  return body.requests;
}

/** Signs in through the mock Keycloak by opening a protected page. */
export async function signIn(page: Page, path = '/', options: MockOptions = {}): Promise<void> {
  await resetMock(options);
  await page.goto(path);
  await expect(page.getByTestId('user-menu')).toBeVisible();
}
