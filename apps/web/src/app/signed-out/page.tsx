import type { Metadata } from 'next';
import type { ReactElement } from 'react';

export const metadata: Metadata = { title: 'Signed out' };

const MESSAGES: Readonly<Record<string, string>> = {
  access_denied: 'Sign-in was cancelled or refused by the identity provider.',
  invalid_state:
    'The sign-in request expired or was not started from this browser. Please try again.',
  token_exchange_failed: 'The identity provider did not complete the sign-in. Please try again.',
  identity_provider_unavailable: 'The identity provider is unavailable. Please try again later.',
};

export default async function SignedOutPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}): Promise<ReactElement> {
  const { error } = await searchParams;
  const message = typeof error === 'string' ? MESSAGES[error] : undefined;
  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md rounded-xl border border-border bg-card p-6">
        <h1 className="text-lg font-semibold">
          {message === undefined ? 'You are signed out' : 'Sign-in failed'}
        </h1>
        <p className="mt-2 text-sm text-muted-foreground">
          {message ??
            'Your session has ended. Sign in again to continue working with the CVE Intelligence Platform.'}
        </p>
        <a
          href="/session/login"
          className="mt-5 inline-flex h-9 items-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Sign in
        </a>
      </div>
    </main>
  );
}
