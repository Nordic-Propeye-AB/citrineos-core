// SPDX-FileCopyrightText: 2026 Contributors to the CitrineOS Project
//
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import { readPublicRuntimeConfig, serializePublicRuntimeConfig } from './runtime-config';

describe('public runtime configuration', () => {
  it('reads provider and endpoints from the running container environment', () => {
    expect(
      readPublicRuntimeConfig({
        NEXT_PUBLIC_AUTH_PROVIDER: 'entra',
        NEXT_PUBLIC_API_URL: 'https://charge-api.prpy.io/v1/graphql',
        NEXT_PUBLIC_WS_URL: 'wss://charge-api.prpy.io/v1/graphql',
        NEXT_PUBLIC_CITRINE_CORE_URL: 'https://charge-api.prpy.io',
      }),
    ).toMatchObject({
      authProvider: 'entra',
      apiUrl: 'https://charge-api.prpy.io/v1/graphql',
      wsUrl: 'wss://charge-api.prpy.io/v1/graphql',
      citrineCoreUrl: 'https://charge-api.prpy.io',
    });
  });

  it('preserves local defaults and rejects an invalid provider instead of bypassing authentication', () => {
    expect(readPublicRuntimeConfig({}).authProvider).toBe('generic');
    expect(() => readPublicRuntimeConfig({ NEXT_PUBLIC_AUTH_PROVIDER: 'entraa' })).toThrow();
  });

  it('does not serialize secrets, even when an environment variable contains a closing script tag', () => {
    const serialized = serializePublicRuntimeConfig({
      NEXT_PUBLIC_CITRINE_CORE_URL: '</script><script>alert(1)</script>',
      NEXTAUTH_SECRET: 'session-secret',
      ENTRA_CLIENT_SECRET: 'client-secret',
      HASURA_ADMIN_SECRET: 'hasura-secret',
    });
    expect(serialized).not.toContain('<');
    expect(serialized).not.toContain('session-secret');
    expect(serialized).not.toContain('client-secret');
    expect(serialized).not.toContain('hasura-secret');
    expect(JSON.parse(serialized).citrineCoreUrl).toBe('</script><script>alert(1)</script>');
  });
});
