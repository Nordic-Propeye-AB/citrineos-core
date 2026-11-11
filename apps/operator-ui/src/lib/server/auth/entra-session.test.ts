// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0

import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { Account, AuthOptions } from 'next-auth';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ keySet: vi.fn() }));
vi.mock('jose', async (importOriginal) => ({
  ...(await importOriginal<typeof import('jose')>()),
  createRemoteJWKSet: () => mocks.keySet,
}));
vi.mock('@lib/utils/config', () => ({ default: { authProvider: 'entra' } }));
vi.mock('@lib/providers/auth-provider/generic-auth-provider', () => ({
  genericAdminUser: { id: 'local' },
}));

const tenantId = '11111111-1111-4111-8111-111111111111';
const clientId = '22222222-2222-4222-8222-222222222222';
const audience = '33333333-3333-4333-8333-333333333333';
let options: AuthOptions;
let accessToken: string;
let unassignedToken: string;

beforeAll(async () => {
  vi.stubEnv('ENTRA_TENANT_ID', tenantId);
  vi.stubEnv('ENTRA_CLIENT_ID', clientId);
  vi.stubEnv('ENTRA_CLIENT_SECRET', 'secret-never-sent-to-browser');
  vi.stubEnv('ENTRA_API_AUDIENCE', audience);
  vi.stubEnv('ENTRA_API_SCOPE', `api://${audience}/access_as_user`);
  vi.stubEnv('NEXT_PUBLIC_TENANT_ID', '1');
  const keys = await generateKeyPair('RS256');
  mocks.keySet.mockImplementation(
    createLocalJWKSet({ keys: [{ ...(await exportJWK(keys.publicKey)), kid: 'session-key' }] }),
  );
  const token = (roles: string[]) =>
    new SignJWT({ tid: tenantId, roles, scp: 'access_as_user' })
      .setProtectedHeader({ alg: 'RS256', kid: 'session-key' })
      .setIssuer(`https://login.microsoftonline.com/${tenantId}/v2.0`)
      .setAudience(audience)
      .setSubject('operator-subject')
      .setExpirationTime('1h')
      .sign(keys.privateKey);
  accessToken = await token(['admin']);
  unassignedToken = await token([]);
  options = (await import('../../../app/api/auth/[...nextauth]/options')).default;
});

afterEach(() => vi.unstubAllGlobals());
afterAll(() => vi.unstubAllEnvs());

const account = (): Account => ({
  provider: 'azure-ad',
  providerAccountId: 'operator-subject',
  type: 'oauth',
  access_token: accessToken,
  refresh_token: 'private-refresh-token',
  id_token: 'provider-validated-id-token',
});

function callbacks() {
  const callbacks = options.callbacks;
  if (!callbacks?.signIn || !callbacks.jwt || !callbacks.session) {
    throw new Error('Missing authentication callbacks');
  }
  return { signIn: callbacks.signIn, jwt: callbacks.jwt, session: callbacks.session };
}

describe('Entra NextAuth sessions', () => {
  it.each([
    ['/partners', 'https://charge.example.com/partners'],
    ['https://charge.example.com/overview', 'https://charge.example.com/overview'],
    ['https://charge.example.com.evil.test/steal', 'https://charge.example.com/overview'],
    ['https://charge.example.com@evil.test/steal', 'https://charge.example.com/overview'],
    ['//evil.test/steal', 'https://charge.example.com/overview'],
    ['/api/auth/callback/azure-ad', 'https://charge.example.com/overview'],
  ])('restricts the post-login redirect %s to the application origin', async (url, expected) => {
    const redirect = options.callbacks?.redirect;
    if (!redirect) {
      throw new Error('Missing redirect callback');
    }
    expect(await redirect({ url, baseUrl: 'https://charge.example.com' })).toBe(expected);
  });

  it('allows assigned operators and refuses roleless users or a local provider', async () => {
    const { signIn } = callbacks();
    expect(await signIn({ user: { id: 'operator' }, account: account() })).toBe(true);
    expect(
      await signIn({
        user: { id: 'operator' },
        account: { ...account(), access_token: unassignedToken },
      }),
    ).toBe(false);
    expect(
      await signIn({ user: { id: 'local' }, account: { ...account(), provider: 'generic' } }),
    ).toBe(false);
  });

  it('keeps refresh tokens and client secrets out of the browser session', async () => {
    const { jwt, session } = callbacks();
    const token = await jwt({
      token: { sub: 'operator-subject' },
      user: { id: 'operator' },
      account: account(),
    });
    expect(token).toMatchObject({
      authProvider: 'entra',
      roles: ['admin'],
      refreshToken: 'private-refresh-token',
    });
    const browserSession = await session({
      session: {
        user: { name: 'Operator' },
        expires: new Date(Date.now() + 3600000).toISOString(),
      },
      token,
      user: { id: 'operator', email: 'operator@example.test', emailVerified: null },
      newSession: undefined,
      trigger: 'update',
    });
    expect(browserSession).toMatchObject({
      accessToken,
      user: { sub: 'operator-subject', roles: ['admin'], tenantId: '1' },
    });
    expect(JSON.stringify(browserSession)).not.toContain('private-refresh-token');
    expect(JSON.stringify(browserSession)).not.toContain('secret-never-sent-to-browser');
  });

  it('rejects sessions issued by local authentication before the provider switched to Entra', async () => {
    const token = await callbacks().jwt({
      token: { sub: 'old-local-user', roles: ['admin'] },
      user: { id: 'old-local-user' },
      account: null,
    });
    expect(token).toEqual({ sub: 'old-local-user', error: 'RefreshAccessTokenError' });
  });

  it('does not expose stale access tokens after Entra requires interaction again', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(Response.json({ error: 'interaction_required' }, { status: 400 })),
    );
    const token = await callbacks().jwt({
      token: {
        sub: 'operator',
        authProvider: 'entra',
        roles: ['admin'],
        accessToken,
        refreshToken: 'private-refresh-token',
        accessTokenExpires: 1,
      },
      user: { id: 'operator' },
      account: null,
    });
    expect(token).toMatchObject({ error: 'RefreshAccessTokenError', roles: [] });
    expect(token.accessToken).toBeUndefined();
    expect(token.refreshToken).toBeUndefined();
  });
});
