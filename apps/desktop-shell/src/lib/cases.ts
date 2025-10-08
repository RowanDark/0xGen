export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export interface CaseEvidence {
  id: string;
  title: string;
  description: string;
  link?: string;
  type: 'network' | 'log' | 'screenshot' | 'artifact' | 'note';
}

export interface CaseDefinition {
  id: string;
  title: string;
  severity: CaseSeverity;
  asset: string;
  tags: string[];
  confidence: number; // 0-100
  summary: string;
  dedupedFindings: string[];
  recommendedActions: string[];
  evidence: CaseEvidence[];
  reproSteps: string[];
  poc: string;
  graph: string;
}

export const CASES: CaseDefinition[] = [
  {
    id: 'CASE-401',
    title: 'Unauthenticated GraphQL schema enumeration',
    severity: 'high',
    asset: 'https://api.finance.internal/graphql',
    tags: ['graphql', 'exposure', 'enumeration'],
    confidence: 88,
    summary:
      'Anonymous clients can introspect the production GraphQL schema, exposing mutation names that allow ledger tampering.',
    dedupedFindings: [
      'Anonymous introspection enabled in production GraphQL gateway',
      'Schema reveals privileged mutation `approveWireTransfer`',
      'Rate limiting disabled for the introspection endpoint'
    ],
    recommendedActions: [
      'Disable anonymous introspection in production gateways',
      'Restrict sensitive mutations to service-to-service OAuth clients',
      'Enable adaptive rate limiting for `/graphql` POST requests'
    ],
    evidence: [
      {
        id: 'EV-112',
        title: 'HTTP 200 response to introspection query',
        description: 'Captured HAR showing anonymous POST request returning full schema.',
        link: 'https://evidence.internal/case401/har',
        type: 'network'
      },
      {
        id: 'EV-113',
        title: 'Screenshot of GraphQL Playground',
        description: 'UI highlights privileged `approveWireTransfer` mutation exposed anonymously.',
        type: 'screenshot'
      }
    ],
    reproSteps: [
      'Send a POST request to `/graphql` with the standard introspection query payload.',
      'Observe the 200 OK response containing `__schema` data.',
      'Review the response for privileged mutations such as `approveWireTransfer`.'
    ],
    poc: `curl -X POST https://api.finance.internal/graphql \\
  -H 'Content-Type: application/json' \\
  --data '{"query":"{ __schema { types { name } } }"}'`,
    graph: `graph TD\n  A[Anonymous Client] -->|POST /graphql| B(GraphQL Gateway)\n  B -->|Forwards query| C(Upstream Schema Registry)\n  C -->|Returns full schema| A`
  },
  {
    id: 'CASE-237',
    title: 'Weak JWT signing secret enables token forgery',
    severity: 'critical',
    asset: 'auth.identity.internal',
    tags: ['jwt', 'crypto', 'critical'],
    confidence: 94,
    summary:
      'Glyph identified that the identity provider signs JWTs with a four-character secret, enabling offline brute-force attacks.',
    dedupedFindings: [
      'HS256 signing secret is four lowercase characters',
      'Rate limiting absent on the `/token` endpoint',
      'Administrative scopes present in forged token sample'
    ],
    recommendedActions: [
      'Rotate to a 256-bit signing secret stored in the KMS',
      'Enforce rate limiting and IP reputation on `/token`',
      'Add anomaly detection for admin scope elevation'
    ],
    evidence: [
      {
        id: 'EV-201',
        title: 'JWT cracking session output',
        description: 'Hashcat logs showing successful secret discovery after 14 seconds.',
        type: 'artifact'
      },
      {
        id: 'EV-202',
        title: 'Forged admin JWT',
        description: 'Token payload contains `scope:admin:*` after offline brute-force.',
        type: 'log'
      }
    ],
    reproSteps: [
      'Capture a legitimate JWT issued by the identity provider.',
      'Run Hashcat with wordlist `rockyou.txt` against the JWT signature.',
      'Construct a forged JWT with `scope:admin:*` and submit it to `/admin/users`.',
      'Observe the successful admin response using the forged token.'
    ],
    poc: `hashcat -m 16500 token.jwt rockyou.txt\nforge-jwt --secret hack --claims '{"scope":"admin:*"}'`,
    graph: `graph TD\n  A[Attacker] -->|Capture JWT| B(Identity Provider)\n  A -->|Brute-force secret| C[Hashcat]\n  C -->|Recovered secret| A\n  A -->|Forge admin token| D(Admin API)\n  D -->|Elevated access| A`
  },
  {
    id: 'CASE-189',
    title: 'Orphaned S3 bucket leaks quarterly forecasts',
    severity: 'medium',
    asset: 's3://finance-forecasts-prod',
    tags: ['s3', 'data-exposure'],
    confidence: 76,
    summary:
      'Discovered a publicly listable S3 bucket containing confidential financial forecasts.',
    dedupedFindings: [
      'Bucket ACL allows anonymous listing',
      'Objects include Q3 and Q4 financial projections',
      'No access logging configured on the bucket'
    ],
    recommendedActions: [
      'Restrict bucket access to the finance AWS account',
      'Enable access logging and object-level encryption',
      'Notify data owners about the exposure'
    ],
    evidence: [
      {
        id: 'EV-301',
        title: 'AWS CLI list-objects output',
        description: 'Command output showing forecast spreadsheets accessible anonymously.',
        type: 'artifact'
      },
      {
        id: 'EV-302',
        title: 'Bucket policy document',
        description: 'Policy grants `s3:*` to `*` principal for legacy migration support.',
        type: 'log'
      }
    ],
    reproSteps: [
      'Run `aws s3 ls s3://finance-forecasts-prod --no-sign-request`.',
      'Download `Q4-forecast.xlsx` anonymously.',
      'Verify the spreadsheet contains confidential forecasts.'
    ],
    poc: `aws s3 cp s3://finance-forecasts-prod/Q4-forecast.xlsx ./ --no-sign-request`,
    graph: `graph TD\n  A[Internet] -->|List bucket| B[S3 Bucket]\n  B -->|Download files| A\n  B -->|No access logs| C[Security Team unaware]`
  }
];
