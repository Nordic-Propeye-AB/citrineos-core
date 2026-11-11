// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';
import type { JWT } from 'next-auth/jwt';
import AzureADProvider from 'next-auth/providers/azure-ad';
import { z } from 'zod';

const configurationSchema = z.object({
  tenantId: z.uuid(),
  clientId: z.uuid(),
  clientSecret: z.string().min(1),
  apiAudience: z.uuid(),
  apiScope: z.string().regex(/^(api:\/\/|https:\/\/)\S+\/[^/\s]+$/),
  allowedRoles: z.array(z.string().min(1)).min(1),
  citrineTenantId: z.string().min(1),
});

export type EntraConfiguration = z.infer<typeof configurationSchema>;

export function readEntraConfiguration(
  environment: Record<string, string | undefined>,
): EntraConfiguration {
  return configurationSchema.parse({
    tenantId: environment.ENTRA_TENANT_ID,
    clientId: environment.ENTRA_CLIENT_ID,
    clientSecret: environment.ENTRA_CLIENT_SECRET,
    apiAudience: environment.ENTRA_API_AUDIENCE,
    apiScope: environment.ENTRA_API_SCOPE,
    allowedRoles: (environment.ENTRA_ALLOWED_ROLES || 'admin,user')
      .split(',')
      .map((role) => role.trim()),
    citrineTenantId: environment['NEXT_PUBLIC_TENANT_ID'] || '1',
  });
}

const issuer = (configuration: EntraConfiguration) =>
  `https://login.microsoftonline.com/${configuration.tenantId}/v2.0`;

export const entraLogoutUrl = (configuration: EntraConfiguration) =>
  `https://login.microsoftonline.com/${configuration.tenantId}/oauth2/v2.0/logout`;

const scopes = (configuration: EntraConfiguration) =>
  `openid profile email offline_access ${configuration.apiScope}`;

const profileSchema = z.object({
  sub: z.string().min(1),
  name: z.string().optional(),
  email: z.string().optional(),
  preferred_username: z.string().optional(),
});

export function createEntraProvider(configuration: EntraConfiguration) {
  return AzureADProvider({
    name: 'Microsoft Entra ID',
    tenantId: configuration.tenantId,
    clientId: configuration.clientId,
    clientSecret: configuration.clientSecret,
    idToken: true,
    checks: ['pkce', 'state', 'nonce'],
    authorization: { params: { scope: scopes(configuration) } },
    // The access token targets CitrineOS, so it cannot be used to fetch a Microsoft Graph photo.
    profile(profile) {
      const claims = profileSchema.parse(profile);
      return {
        id: claims.sub,
        name: claims.name || claims.preferred_username || claims.sub,
        email: claims.email || null,
        image: null,
      };
    },
  });
}

const keySets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function entraKeySet(configuration: EntraConfiguration) {
  const url = `https://login.microsoftonline.com/${configuration.tenantId}/discovery/v2.0/keys`;
  let keySet = keySets.get(url);
  if (!keySet) {
    keySet = createRemoteJWKSet(new URL(url));
    keySets.set(url, keySet);
  }
  return keySet;
}

export async function verifyEntraAccessToken(
  accessToken: string,
  configuration: EntraConfiguration,
  keySet: JWTVerifyGetKey = entraKeySet(configuration),
) {
  const { payload } = await jwtVerify(accessToken, keySet, {
    algorithms: ['RS256'],
    issuer: issuer(configuration),
    audience: configuration.apiAudience,
    requiredClaims: ['exp', 'sub', 'tid', 'roles', 'scp'],
  });
  const claims = z
    .object({
      exp: z.number().int(),
      tid: z.literal(configuration.tenantId),
      roles: z.array(z.string()),
      scp: z.string(),
    })
    .parse(payload);
  const roles = claims.roles.filter((role) => configuration.allowedRoles.includes(role));
  const scope = configuration.apiScope.slice(configuration.apiScope.lastIndexOf('/') + 1);
  if (roles.length === 0 || !claims.scp.split(' ').includes(scope)) {
    throw new Error('Entra token does not grant an allowed CitrineOS role and delegated scope');
  }
  return {
    roles,
    tenantId: configuration.citrineTenantId,
    accessTokenExpires: claims.exp * 1000,
  };
}

const refreshResponseSchema = z.object({
  access_token: z.string().min(1),
  expires_in: z.number().positive(),
  refresh_token: z.string().min(1).optional(),
});

export async function refreshEntraAccessToken(
  token: JWT,
  configuration: EntraConfiguration,
  keySet?: JWTVerifyGetKey,
): Promise<JWT> {
  try {
    if (!token.refreshToken) {
      throw new Error('Missing refresh token');
    }
    const response = await fetch(
      `https://login.microsoftonline.com/${configuration.tenantId}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: configuration.clientId,
          client_secret: configuration.clientSecret,
          grant_type: 'refresh_token',
          refresh_token: token.refreshToken,
          scope: scopes(configuration),
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!response.ok) {
      throw new Error('Entra refresh request failed');
    }
    const body: unknown = await response.json();
    const refreshed = refreshResponseSchema.parse(body);
    const permissions = await verifyEntraAccessToken(refreshed.access_token, configuration, keySet);
    return {
      ...token,
      ...permissions,
      accessToken: refreshed.access_token,
      accessTokenExpires: Math.min(
        permissions.accessTokenExpires,
        Date.now() + refreshed.expires_in * 1000,
      ),
      refreshToken: refreshed.refresh_token || token.refreshToken,
      error: undefined,
    };
  } catch {
    return {
      ...token,
      accessToken: undefined,
      idToken: undefined,
      refreshToken: undefined,
      accessTokenExpires: 0,
      roles: [],
      error: 'RefreshAccessTokenError',
    };
  }
}
