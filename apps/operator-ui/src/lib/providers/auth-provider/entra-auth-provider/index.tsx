// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0
'use client';

import { Button } from '@lib/client/components/ui/button';
import type { AuthenticationContextProvider, User } from '@lib/utils/access-types';
import { HasuraHeader, HasuraRole } from '@lib/utils/hasura-types';
import { type AuthProvider, useTranslate } from '@refinedev/core';
import { getSession, signIn, signOut } from 'next-auth/react';
import React from 'react';

const EntraLoginPage = () => {
  const translate = useTranslate();

  return (
    <div className="flex min-h-screen items-center justify-center">
      <Button onClick={() => signIn('azure-ad', { callbackUrl: '/overview' })}>
        {translate('pages.login.signInWithEntra')}
      </Button>
    </div>
  );
};

export function createEntraAuthProvider(): AuthProvider & AuthenticationContextProvider {
  const getPermissions = async () => ({ roles: (await getSession())?.user?.roles || [] });
  const getUserRole = async () => {
    const { roles } = await getPermissions();

    return roles.includes(HasuraRole.ADMIN)
      ? HasuraRole.ADMIN
      : roles.includes(HasuraRole.USER)
        ? HasuraRole.USER
        : undefined;
  };
  return {
    login: async ({ redirectTo }) => {
      await signIn('azure-ad', { callbackUrl: redirectTo || '/overview' });
      return { success: true };
    },
    logout: async () => {
      const session = await getSession();
      await signOut({ redirect: false });

      if (session?.entraLogoutUrl) {
        const url = new URL(session.entraLogoutUrl);
        url.searchParams.set('post_logout_redirect_uri', `${window.location.origin}/login`);
        window.location.assign(url.toString());
      }

      return { success: true, redirectTo: '/login' };
    },
    check: async () => {
      const session = await getSession();

      if (!session?.accessToken || session.error || !session.user?.roles?.length) {
        return { authenticated: false, logout: true, redirectTo: '/login' };
      }

      return { authenticated: true };
    },
    getIdentity: async (): Promise<User | null> => {
      const user = (await getSession())?.user;

      if (!user?.sub) {
        return null;
      }

      return {
        id: user.sub,
        name: user.name || '',
        email: user.email || undefined,
        roles: user.roles || [],
      };
    },
    getPermissions,
    onError: async (error) => (error.statusCode === 401 ? { logout: true } : { error }),
    getToken: async () => (await getSession())?.accessToken,
    getUserRole,
    getHasuraHeaders: async () => {
      const session = await getSession();
      const headers = new Map<HasuraHeader, string>();
      const role = await getUserRole();

      if (role) {
        headers.set(HasuraHeader.X_HASURA_ROLE, role);
      }

      if (session?.user?.tenantId) {
        headers.set(HasuraHeader.X_HASURA_TENANT_ID, session.user.tenantId);
      }
      return headers;
    },
    getInitialized: async () => true,
    getLoginPage: () => EntraLoginPage,
  };
}
