// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0

import { AuthProviderTypeEnum } from '../providers/auth-provider/types';

export function readPublicRuntimeConfig(environment: Record<string, string | undefined>) {
  return {
    authProvider: AuthProviderTypeEnum.parse(environment['NEXT_PUBLIC_AUTH_PROVIDER'] || 'generic'),
    apiUrl: environment['NEXT_PUBLIC_API_URL'],
    wsUrl: environment['NEXT_PUBLIC_WS_URL'],
    citrineCoreUrl: environment['NEXT_PUBLIC_CITRINE_CORE_URL'],
    tenantId: environment['NEXT_PUBLIC_TENANT_ID'],
    keycloakUrl: environment['NEXT_PUBLIC_KEYCLOAK_URL'],
  };
}

export type PublicRuntimeConfig = ReturnType<typeof readPublicRuntimeConfig>;

declare global {
  interface Window {
    __CITRINE_PUBLIC_CONFIG__?: PublicRuntimeConfig;
  }
}

export function serializePublicRuntimeConfig(environment: Record<string, string | undefined>) {
  return JSON.stringify(readPublicRuntimeConfig(environment)).replace(/</g, '\\u003c');
}
