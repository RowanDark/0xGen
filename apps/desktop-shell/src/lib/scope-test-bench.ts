export type ScopeBenchmark = {
  id: string;
  label: string;
  description: string;
  text: string;
  expectedPolicy: string;
  notes?: string;
};

export const scopeBenchmarks: ScopeBenchmark[] = [
  {
    id: 'saas-production',
    label: 'SaaS production surface',
    description:
      'Allow production web and API endpoints while keeping admin and staging assets out of scope.',
    notes:
      'Based on a typical SaaS brief that limits testing to customer-facing hosts and forbids touching staff tools.',
    text: `Our program covers customer-facing properties only. Please focus on https://app.acme.inc and the public API under https://api.acme.inc. Administrative portals (admin.acme.inc) and staging hosts (*.staging.acme.inc) are explicitly out of scope. Private network ranges remain forbidden.`,
    expectedPolicy: `version: 1
allow:
  - type: url_prefix
    value: https://app.acme.inc
  - type: url_prefix
    value: https://api.acme.inc
deny:
  - type: url_prefix
    value: https://admin.acme.inc
  - type: wildcard
    value: *.staging.acme.inc
private_networks: block`
  },
  {
    id: 'marketing-only',
    label: 'Marketing site only',
    description: 'Marketing content is in scope; checkout and payment infrastructure are excluded.',
    notes:
      'Designed to ensure the LLM clearly separates public marketing pages from sensitive payment domains.',
    text: `Testing is limited to the marketing site at https://www.banner.example. Do not touch store.banner.example or any payment processors under pay.banner.example. Internal VPN and RFC1918 ranges are also off limits.`,
    expectedPolicy: `version: 1
allow:
  - type: url_prefix
    value: https://www.banner.example
deny:
  - type: url_prefix
    value: https://store.banner.example
  - type: url_prefix
    value: https://pay.banner.example
private_networks: block`
  },
  {
    id: 'broad-wildcard',
    label: 'Wildcard heavy program',
    description: 'Large programs sometimes permit wildcard discovery with carve-outs.',
    notes:
      'Used to verify that wildcard suggestions remain accurate and call for human confirmation.',
    text: `In scope: *.orbit.dev, including blogs and docs. Excluded assets: payments.orbit.dev and anything on legacy.orbit.dev. Collecting PII is not allowed.`,
    expectedPolicy: `version: 1
allow:
  - type: wildcard
    value: *.orbit.dev
deny:
  - type: url_prefix
    value: https://payments.orbit.dev
  - type: wildcard
    value: *.legacy.orbit.dev
pii: forbid`
  }
];
