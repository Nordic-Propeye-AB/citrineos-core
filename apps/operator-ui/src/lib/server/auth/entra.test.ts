// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0

import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTPayload } from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  createEntraProvider,
  readEntraConfiguration,
  refreshEntraAccessToken,
  verifyEntraAccessToken,
} from './entra';

const environment = {
  ENTRA_TENANT_ID: '11111111-1111-4111-8111-111111111111',
  ENTRA_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
  ENTRA_CLIENT_SECRET: 'test-client-secret',
  ENTRA_API_AUDIENCE: '33333333-3333-4333-8333-333333333333',
  ENTRA_API_SCOPE: 'api://33333333-3333-4333-8333-333333333333/access_as_user',
  NEXT_PUBLIC_TENANT_ID: '7',
};
const configuration = readEntraConfiguration(environment);
const issuer = `https://login.microsoftonline.com/${configuration.tenantId}/v2.0`;
let keyPair: Awaited<ReturnType<typeof generateKeyPair>>;
let keySet: ReturnType<typeof createLocalJWKSet>;

beforeAll(async () => {
  keyPair = await generateKeyPair('RS256');
  keySet = createLocalJWKSet({
    keys: [{ ...(await exportJWK(keyPair.publicKey)), kid: 'test-key' }],
  });
});

afterEach(() => vi.unstubAllGlobals());

async function signedToken(overrides: JWTPayload = {}) {
  return new SignJWT({
    iss: issuer,
    aud: configuration.apiAudience,
    sub: 'operator-subject',
    tid: configuration.tenantId,
    roles: ['admin'],
    scp: 'access_as_user',
    exp: Math.floor(Date.now() / 1000) + 3600,
    ...overrides,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .sign(keyPair.privateKey);
}

describe('Entra authentication', () => {
  it('requires a specific tenant and the CitrineOS API resource', () => {
    expect(() => readEntraConfiguration({ ...environment, ENTRA_TENANT_ID: 'common' })).toThrow();
    expect(() => readEntraConfiguration({ ...environment, ENTRA_API_AUDIENCE: '' })).toThrow();
    expect(() =>
      readEntraConfiguration({ ...environment, ENTRA_API_SCOPE: 'User.Read' }),
    ).toThrow();
  });

  it('requests offline access and the delegated API scope with PKCE, state, and nonce', () => {
    const provider = createEntraProvider(configuration);
    expect(provider.options).toMatchObject({
      tenantId: configuration.tenantId,
      authorization: {
        params: { scope: expect.stringContaining(`offline_access ${configuration.apiScope}`) },
      },
      checks: ['pkce', 'state', 'nonce'],
      idToken: true,
    });
  });

  it('accepts a signed API token with an assigned role and uses the CitrineOS tenant', async () => {
    const accessToken = await signedToken();
    await expect(verifyEntraAccessToken(accessToken, configuration, keySet)).resolves.toMatchObject(
      {
        roles: ['admin'],
        tenantId: '7',
      },
    );
  });

  it.each([
    { aud: configuration.clientId },
    { aud: '00000003-0000-0000-c000-000000000000' },
    { iss: 'https://another-issuer.example' },
    { tid: '44444444-4444-4444-8444-444444444444' },
    { exp: 1 },
    { roles: [] },
    { roles: ['unassigned'] },
    { roles: 'admin' },
    { scp: 'another_scope' },
    { scp: undefined },
  ])('rejects wrong audiences, issuers, tenants, expiry, roles, and scopes: %j', async (claims) => {
    const accessToken = await signedToken(claims);
    await expect(verifyEntraAccessToken(accessToken, configuration, keySet)).rejects.toThrow();
  });

  it('rejects a token signed by another key', async () => {
    const otherKey = await generateKeyPair('RS256');
    const accessToken = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .sign(otherKey.privateKey);
    await expect(verifyEntraAccessToken(accessToken, configuration, keySet)).rejects.toThrow();
  });

  it('rotates the refresh token and refreshes roles from a verified access token', async () => {
    const accessToken = await signedToken({ roles: ['user'] });
    const fetchMock = vi.fn().mockResolvedValue(
      Response.json({
        access_token: accessToken,
        refresh_token: 'rotated-refresh-token',
        expires_in: 3600,
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const refreshed = await refreshEntraAccessToken(
      { refreshToken: 'old-refresh-token' },
      configuration,
      keySet,
    );
    expect(refreshed).toMatchObject({
      accessToken,
      refreshToken: 'rotated-refresh-token',
      roles: ['user'],
      tenantId: '7',
    });
    expect(refreshed.error).toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      `https://login.microsoftonline.com/${configuration.tenantId}/oauth2/v2.0/token`,
      expect.objectContaining({ body: expect.any(URLSearchParams) }),
    );
  });

  it('retains the refresh token when Entra does not rotate it', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        Response.json({
          access_token: await signedToken(),
          expires_in: 3600,
        }),
      ),
    );
    const refreshed = await refreshEntraAccessToken(
      { refreshToken: 'old-refresh-token' },
      configuration,
      keySet,
    );
    expect(refreshed.refreshToken).toBe('old-refresh-token');
  });

  it.each(['revoked', 'malformed', 'wrong-audience', 'roles-revoked'])(
    'clears tokens after a failed refresh: %s',
    async (failure) => {
      const response =
        failure === 'revoked'
          ? Response.json({ error: 'invalid_grant' }, { status: 400 })
          : failure === 'malformed'
            ? Response.json({ access_token: 'not-a-jwt' })
            : Response.json({
                access_token: await signedToken(
                  failure === 'wrong-audience' ? { aud: configuration.clientId } : { roles: [] },
                ),
                expires_in: 3600,
              });
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response));
      const refreshed = await refreshEntraAccessToken(
        {
          accessToken: 'old-access',
          refreshToken: 'old-refresh',
          idToken: 'old-id',
          roles: ['admin'],
        },
        configuration,
        keySet,
      );
      expect(refreshed).toMatchObject({
        error: 'RefreshAccessTokenError',
        roles: [],
        accessTokenExpires: 0,
      });
      expect(refreshed.accessToken).toBeUndefined();
      expect(refreshed.refreshToken).toBeUndefined();
      expect(refreshed.idToken).toBeUndefined();
    },
  );
});
