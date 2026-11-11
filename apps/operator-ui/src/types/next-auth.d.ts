// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0

import type { DefaultSession } from 'next-auth';

declare module 'next-auth' {
  interface Session {
    user?: DefaultSession['user'] & {
      sub?: string;
      roles?: string[];
      tenantId?: string;
    };
    accessToken?: string;
    idToken?: string;
    keycloakLogoutUrl?: string;
    entraLogoutUrl?: string;
    error?: string;
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    authProvider?: 'entra';
    accessToken?: string;
    idToken?: string;
    refreshToken?: string;
    accessTokenExpires?: number;
    roles?: string[];
    tenantId?: string;
    keycloakLogoutUrl?: string;
    entraLogoutUrl?: string;
    error?: 'RefreshAccessTokenError';
  }
}
