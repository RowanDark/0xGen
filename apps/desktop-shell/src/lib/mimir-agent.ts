type AgentMessage = {
  role: 'user' | 'assistant';
  content: string;
};

type AgentLimits = {
  concurrency: number;
  maxRps: number;
  maxFindings: number;
  safeMode: boolean;
};

export type MimirAgentContext = {
  scopePolicy: string;
  targets: string[];
  targetNotes?: string;
  plugins: string[];
  limits: AgentLimits;
};

export type MimirRecommendation = {
  id: string;
  title: string;
  description: string;
  plugins: string[];
  rationale: string;
  nextScan?: string;
};

export type MimirAgentResponse = {
  message: string;
  recommendations: MimirRecommendation[];
  followUps: string[];
};

type AgentIntent = 'context' | 'chat';

type AgentInput = {
  intent: AgentIntent;
  context: MimirAgentContext;
  messages: AgentMessage[];
};

type RecommendationRule = (context: MimirAgentContext) => MimirRecommendation | null;

const pluginNameMap: Record<string, string> = {
  'http-crawler': 'HTTP Crawler',
  'secrets-scanner': 'Secrets Scanner',
  'form-fuzzer': 'Form Fuzzer',
  'js-runtime': 'Browser Runtime',
  'traffic-recorder': 'Traffic Recorder'
};

const recommendationRules: RecommendationRule[] = [
  (context) => {
    const required = ['http-crawler', 'secrets-scanner'];
    const missing = required.filter((plugin) => !context.plugins.includes(plugin));
    if (missing.length === 0) {
      return null;
    }
    return {
      id: 'discovery-baseline',
      title: 'Discovery baseline',
      description: 'Ensure crawl coverage pairs with a secrets sweep so new paths get triaged immediately.',
      plugins: required,
      rationale:
        missing.length === 1
          ? `${pluginNameMap[missing[0]!] ?? missing[0]!} is missing, so exposures along discovered routes may be overlooked.`
          : 'Discovery plus a secrets pass establishes a fast feedback loop for leaked credentials.',
      nextScan: 'Follow up with Traffic Recorder to capture a baseline replay after discovery completes.'
    };
  },
  (context) => {
    if (!context.plugins.includes('http-crawler') || context.plugins.includes('form-fuzzer')) {
      return null;
    }
    return {
      id: 'crawler-fuzzer',
      title: 'Crawler + Form Fuzzer',
      description: 'Let the crawler populate form targets, then unleash the fuzzer against authenticated flows.',
      plugins: ['http-crawler', 'form-fuzzer'],
      rationale: 'Forms surfaced by discovery rarely get fuzzed immediately; chaining these keeps findings fresh.',
      nextScan: 'Queue a second fuzz-only run at lower concurrency to validate high-risk payloads once triaged.'
    };
  },
  (context) => {
    const targetHint = context.targets.some((target) => /login|auth|account|signin|oauth/i.test(target));
    if (!targetHint) {
      return null;
    }
    const combo = Array.from(new Set(['js-runtime', 'form-fuzzer'])) as string[];
    const missing = combo.filter((plugin) => !context.plugins.includes(plugin));
    if (missing.length === 0) {
      return null;
    }
    return {
      id: 'session-hardening',
      title: 'Session hardening sweep',
      description: 'Blend runtime scripts with fuzzing to stress login and session handling paths.',
      plugins: combo,
      rationale:
        missing.length === combo.length
          ? 'Dynamic auth flows need scripted session handling before fuzzing brings value.'
          : `${pluginNameMap[missing[0]!] ?? missing[0]!} closes the gap on dynamic session coverage.`,
      nextScan: 'Plan a credential stuffing simulation using passive traffic captures once auth automation is stable.'
    };
  },
  (context) => {
    const apiTargets = context.targets.some((target) => /api|graphql|gateway|service|backend/i.test(target));
    if (!apiTargets && context.scopePolicy !== 'broad') {
      return null;
    }
    const combo = Array.from(new Set(['traffic-recorder', 'secrets-scanner'])) as string[];
    const missing = combo.filter((plugin) => !context.plugins.includes(plugin));
    if (missing.length === 0) {
      return null;
    }
    return {
      id: 'api-observability',
      title: 'API observability pack',
      description: 'Capture live calls while scanning for sensitive responses to baseline noisy backends.',
      plugins: combo,
      rationale: `${pluginNameMap[missing[0]!] ?? missing[0]!} is required to keep leaked tokens visible across API replay runs.`,
      nextScan: 'Schedule a replay-only pass after peak hours to validate throttling and cache behaviour.'
    };
  },
  (context) => {
    if (context.limits.safeMode || context.plugins.includes('traffic-recorder')) {
      return null;
    }
    return {
      id: 'passive-precheck',
      title: 'Passive pre-check',
      description: 'Add passive telemetry before aggressive tools since safe mode is disabled.',
      plugins: ['traffic-recorder'],
      rationale: 'Without safe mode, a passive recorder reduces blast radius by observing first.',
      nextScan: 'Run the aggressive stack after reviewing captured responses for unexpected behaviours.'
    };
  }
];

function describeScope(scopePolicy: string): string {
  switch (scopePolicy) {
    case 'strict':
      return 'strict production';
    case 'staging':
      return 'staging-aligned';
    case 'broad':
      return 'broad discovery';
    default:
      return scopePolicy;
  }
}

function describeTargets(targets: string[]): string {
  if (targets.length === 0) {
    return 'no explicit targets yet';
  }
  const hostnames = targets
    .map((target) => target.trim())
    .filter(Boolean)
    .map((target) => target.replace(/^https?:\/\//i, ''));
  if (hostnames.length === 0) {
    return 'no explicit targets yet';
  }
  if (hostnames.length === 1) {
    return hostnames[0]!;
  }
  return `${hostnames[0]!} plus ${hostnames.length - 1} more`;
}

function fingerprintContext(context: MimirAgentContext): string {
  const sortedTargets = [...context.targets].map((target) => target.trim()).filter(Boolean).sort();
  const sortedPlugins = [...context.plugins].sort();
  return JSON.stringify({
    scopePolicy: context.scopePolicy,
    targets: sortedTargets,
    plugins: sortedPlugins,
    safeMode: context.limits.safeMode,
    concurrency: context.limits.concurrency,
    maxRps: context.limits.maxRps,
    maxFindings: context.limits.maxFindings,
    targetNotes: context.targetNotes?.trim() ?? ''
  });
}

export function buildContextFingerprint(context: MimirAgentContext): string {
  return fingerprintContext(context);
}

function buildSecurityReasoning(context: MimirAgentContext, recommendationCount: number): string[] {
  const notes: string[] = [];
  notes.push(`Scope policy signals a ${describeScope(context.scopePolicy)} posture.`);
  if (context.plugins.length === 0) {
    notes.push('No plugins are enabled yet, so the run would be a no-op without adjustments.');
  } else {
    notes.push(`Selected plugins (${context.plugins.join(', ')}) cover ${recommendationCount > 0 ? 'part' : 'most'} of the discovery pipeline.`);
  }
  notes.push(
    context.limits.safeMode
      ? 'Safe mode keeps high-risk actions throttled.'
      : 'Safe mode is off, so treat payload-heavy tooling with change control.'
  );
  return notes;
}

function computeRecommendations(context: MimirAgentContext): MimirRecommendation[] {
  const seen = new Set<string>();
  const results: MimirRecommendation[] = [];
  for (const rule of recommendationRules) {
    const recommendation = rule(context);
    if (!recommendation) {
      continue;
    }
    if (seen.has(recommendation.id)) {
      continue;
    }
    seen.add(recommendation.id);
    results.push(recommendation);
    if (results.length >= 4) {
      break;
    }
  }
  return results;
}

export async function runMimirAgent(input: AgentInput): Promise<MimirAgentResponse> {
  const { context, messages, intent } = input;
  const recommendations = computeRecommendations(context);
  const fingerprint = fingerprintContext(context);

  const lastUserMessage = [...messages].reverse().find((message) => message.role === 'user');
  const userQuestion = lastUserMessage?.content?.trim();

  const scopeDescriptor = describeScope(context.scopePolicy);
  const targetDescriptor = describeTargets(context.targets);
  const pluginSummary = context.plugins.length > 0 ? context.plugins.join(', ') : 'no tooling yet';
  const safeModeNote = context.limits.safeMode
    ? 'Safe mode is enabled, so high-risk payloads will stay throttled.'
    : 'Safe mode is disabled; ensure change windows are open before adding aggressive plugins.';

  const topRecommendation = recommendations[0];
  const comboSummary = recommendations
    .map((rec) => `${rec.title} (${rec.plugins.map((plugin) => pluginNameMap[plugin] ?? plugin).join(', ')})`)
    .join('; ');

  const intro = intent === 'chat' && userQuestion
    ? `You asked: “${userQuestion}”.`
    : `Current configuration fingerprint ${fingerprint.slice(0, 8)}…`;

  const contextLine = `We are operating with the ${scopeDescriptor} template against ${targetDescriptor}, ` +
    `with ${context.plugins.length} plugin${context.plugins.length === 1 ? '' : 's'} enabled (${pluginSummary}).`;

  const recommendationLine = recommendations.length > 0
    ? `I'd prioritise ${topRecommendation!.title.toLowerCase()} and keep ${comboSummary} in the queue.`
    : 'The enabled plugins already cover discovery, secrets, and runtime execution—consider scheduling a passive verification run next.';

  const notes = buildSecurityReasoning(context, recommendations.length);
  if (context.targetNotes?.trim()) {
    notes.push(`Operator notes mention: ${context.targetNotes.trim()}`);
  }

  const message = [intro, contextLine, recommendationLine, safeModeNote, 'Security reasoning:', ...notes.map((note) => `• ${note}`)]
    .filter(Boolean)
    .join('\n');

  const followUps = recommendations
    .map((rec) => rec.nextScan)
    .filter((nextScan): nextScan is string => Boolean(nextScan));

  // Simulate async agent latency for UX parity with real LLM calls.
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({
        message,
        recommendations,
        followUps
      });
    }, intent === 'chat' ? 400 : 250);
  });
}
