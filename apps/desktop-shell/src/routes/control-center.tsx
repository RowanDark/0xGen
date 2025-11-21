import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { motion, useReducedMotion } from 'framer-motion';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Brain,
  Bug,
  CheckCircle2,
  ChevronRight,
  Clock,
  Code,
  Database,
  Eye,
  FileSearch,
  Fingerprint,
  GitBranch,
  Globe,
  Key,
  Layers,
  Lock,
  Map,
  Network,
  Play,
  Puzzle,
  Search,
  Settings,
  Shield,
  Sparkles,
  Target,
  Terminal,
  TrendingUp,
  Zap
} from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '../components/ui/button';
import {
  fetchPluginRegistryData,
  type InstalledPluginSummary,
  type PluginRegistry
} from '../lib/ipc';
import { cn } from '../lib/utils';
import { baseTransition, hoverTransition } from '../lib/motion';
import { PipelineFlow } from '../components/pipeline-flow';

// Plugin metadata with icons and descriptions
const PLUGIN_METADATA: Record<
  string,
  {
    icon: typeof Brain;
    color: string;
    gradient: string;
    category: string;
    description: string;
    actions: { label: string; route: string }[];
  }
> = {
  hydra: {
    icon: Brain,
    color: 'text-purple-500',
    gradient: 'from-purple-500 to-pink-500',
    category: 'Detection',
    description: 'AI-powered vulnerability detection (XSS, SQLi, SSRF)',
    actions: [
      { label: 'View Findings', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  seer: {
    icon: Eye,
    color: 'text-blue-500',
    gradient: 'from-blue-500 to-cyan-500',
    category: 'Detection',
    description: 'Secrets & PII detection using entropy heuristics',
    actions: [
      { label: 'View Secrets', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  entropy: {
    icon: TrendingUp,
    color: 'text-emerald-500',
    gradient: 'from-emerald-500 to-teal-500',
    category: 'Analysis',
    description: 'Shannon entropy analysis for obfuscation detection',
    actions: [
      { label: 'View Analysis', route: '/entropy' },
      { label: 'Sessions', route: '/entropy' }
    ]
  },
  keys: {
    icon: Key,
    color: 'text-amber-500',
    gradient: 'from-amber-500 to-orange-500',
    category: 'Detection',
    description: 'Cryptographic key & token extraction',
    actions: [
      { label: 'View Keys', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  cartographer: {
    icon: Map,
    color: 'text-indigo-500',
    gradient: 'from-indigo-500 to-purple-500',
    category: 'Discovery',
    description: 'Application surface mapping & asset discovery',
    actions: [
      { label: 'View Map', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  excavator: {
    icon: FileSearch,
    color: 'text-rose-500',
    gradient: 'from-rose-500 to-pink-500',
    category: 'Analysis',
    description: 'Structured data extraction from responses',
    actions: [
      { label: 'View Data', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  cryptographer: {
    icon: Lock,
    color: 'text-violet-500',
    gradient: 'from-violet-500 to-purple-500',
    category: 'Analysis',
    description: 'Cipher identification & crypto analysis',
    actions: [
      { label: 'View Analysis', route: '/cipher' },
      { label: 'Recipes', route: '/cipher' }
    ]
  },
  grapher: {
    icon: GitBranch,
    color: 'text-sky-500',
    gradient: 'from-sky-500 to-blue-500',
    category: 'Visualization',
    description: 'Relationship graphing & dependency visualization',
    actions: [
      { label: 'View Graphs', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  ranker: {
    icon: Target,
    color: 'text-red-500',
    gradient: 'from-red-500 to-rose-500',
    category: 'Analysis',
    description: 'CVSS-based vulnerability prioritization',
    actions: [
      { label: 'View Rankings', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  raider: {
    icon: Zap,
    color: 'text-orange-500',
    gradient: 'from-orange-500 to-red-500',
    category: 'Offensive',
    description: 'Offensive testing orchestration',
    actions: [
      { label: 'Launch', route: '/runs/composer' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  'osint-well': {
    icon: Globe,
    color: 'text-cyan-500',
    gradient: 'from-cyan-500 to-teal-500',
    category: 'Intelligence',
    description: 'Public threat intelligence aggregation',
    actions: [
      { label: 'View Intel', route: '/cases' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  'galdr-proxy': {
    icon: Network,
    color: 'text-fuchsia-500',
    gradient: 'from-fuchsia-500 to-pink-500',
    category: 'Interception',
    description: 'HTTP/HTTPS MITM interception engine',
    actions: [
      { label: 'View Flows', route: '/flows' },
      { label: 'Configure', route: '/plugins' }
    ]
  },
  scribe: {
    icon: FileSearch,
    color: 'text-slate-500',
    gradient: 'from-slate-500 to-gray-500',
    category: 'Reporting',
    description: 'Report generation (SARIF, JSON, HTML, PDF)',
    actions: [
      { label: 'Generate', route: '/cases' },
      { label: 'Templates', route: '/plugins' }
    ]
  }
};

// Fallback metadata for unknown plugins
const DEFAULT_PLUGIN_METADATA = {
  icon: Puzzle,
  color: 'text-gray-500',
  gradient: 'from-gray-500 to-slate-500',
  category: 'Other',
  description: 'Security testing plugin',
  actions: [
    { label: 'View Details', route: '/plugins' },
    { label: 'Configure', route: '/plugins' }
  ]
};

type PluginCardProps = {
  plugin: InstalledPluginSummary;
  index: number;
};

function PluginCard({ plugin, index }: PluginCardProps) {
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();
  const metadata = PLUGIN_METADATA[plugin.id] ?? DEFAULT_PLUGIN_METADATA;
  const Icon = metadata.icon;

  return (
    <motion.div
      initial={shouldReduceMotion ? false : { opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={shouldReduceMotion ? { duration: 0 } : { ...baseTransition, delay: index * 0.05 }}
      className="group relative flex h-full flex-col overflow-hidden rounded-2xl border border-border/70 bg-card/95 shadow-soft backdrop-blur-sm transition-all hover:shadow-xl"
    >
      {/* Header with gradient */}
      <div
        className={cn(
          'relative border-b border-border/70 px-6 py-5',
          'bg-gradient-to-br',
          `${metadata.gradient} bg-opacity-10`
        )}
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                'flex h-12 w-12 items-center justify-center rounded-xl bg-white/90 shadow-lg ring-1 ring-black/5',
                'dark:bg-gray-900/90'
              )}
            >
              <Icon className={cn('h-6 w-6', metadata.color)} strokeWidth={2} />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-foreground">{plugin.name}</h3>
              <p className="text-xs text-muted-foreground">v{plugin.version}</p>
            </div>
          </div>
          <span
            className={cn(
              'inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold',
              'bg-primary/10 text-primary ring-1 ring-inset ring-primary/20'
            )}
          >
            {metadata.category}
          </span>
        </div>
      </div>

      {/* Body */}
      <div className="flex flex-1 flex-col gap-4 px-6 py-5">
        <p className="text-sm text-muted-foreground">{metadata.description}</p>

        {/* Capabilities */}
        <div className="flex flex-wrap gap-2">
          {plugin.capabilities.slice(0, 4).map((cap) => (
            <span
              key={cap}
              className={cn(
                'inline-flex items-center rounded-md px-2 py-1 text-[0.65rem] font-medium',
                'bg-muted/60 text-muted-foreground ring-1 ring-inset ring-border/50'
              )}
            >
              {cap.replace('CAP_', '').replace(/_/g, ' ').toLowerCase()}
            </span>
          ))}
          {plugin.capabilities.length > 4 && (
            <span className="inline-flex items-center rounded-md px-2 py-1 text-[0.65rem] font-medium text-muted-foreground">
              +{plugin.capabilities.length - 4} more
            </span>
          )}
        </div>

        {/* Status indicator */}
        <div className="mt-auto flex items-center gap-2 text-xs">
          <div className="flex items-center gap-1.5">
            <div className="h-2 w-2 rounded-full bg-emerald-500 shadow-sm ring-2 ring-emerald-500/20" />
            <span className="font-medium text-foreground">Installed</span>
          </div>
          <span className="text-muted-foreground">•</span>
          <span className="text-muted-foreground">Last updated: {plugin.updatedAt ? new Date(plugin.updatedAt).toLocaleDateString() : 'Unknown'}</span>
        </div>
      </div>

      {/* Actions footer */}
      <div className="border-t border-border/70 bg-muted/20 px-6 py-4">
        <div className="flex items-center gap-2">
          {metadata.actions.map((action, idx) => (
            <Button
              key={idx}
              size="sm"
              variant={idx === 0 ? 'default' : 'outline'}
              className={cn('gap-1.5', idx === 0 && `bg-gradient-to-r ${metadata.gradient} text-white hover:opacity-90`)}
              onClick={() => navigate({ to: action.route })}
            >
              {action.label}
              <ChevronRight className="h-3 w-3" />
            </Button>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

type QuickActionProps = {
  icon: typeof Activity;
  label: string;
  description: string;
  route: string;
  color: string;
  gradient: string;
};

function QuickAction({ icon: Icon, label, description, route, color, gradient }: QuickActionProps) {
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();

  return (
    <motion.button
      type="button"
      onClick={() => navigate({ to: route })}
      whileHover={shouldReduceMotion ? undefined : { y: -4, transition: hoverTransition }}
      whileTap={shouldReduceMotion ? undefined : { scale: 0.98 }}
      className={cn(
        'group relative flex flex-col gap-3 rounded-xl border border-border/70 bg-card/95 p-5 text-left shadow-soft backdrop-blur-sm transition-all',
        'hover:border-primary/60 hover:shadow-xl',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2'
      )}
    >
      <div className="flex items-start justify-between">
        <div className={cn('flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br', gradient)}>
          <Icon className="h-5 w-5 text-white" strokeWidth={2} />
        </div>
        <ChevronRight className={cn('h-5 w-5 transition-transform group-hover:translate-x-1', color)} />
      </div>
      <div>
        <h4 className="font-semibold text-foreground">{label}</h4>
        <p className="mt-1 text-sm text-muted-foreground">{description}</p>
      </div>
    </motion.button>
  );
}

function ControlCenterRoute() {
  const [registry, setRegistry] = useState<PluginRegistry | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchPluginRegistryData();
      setRegistry(data);
      setError(null);
    } catch (rawError) {
      const message = rawError instanceof Error ? rawError.message : String(rawError);
      setError(message);
      toast.error('Failed to load plugin registry');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const installedPlugins = useMemo(() => registry?.installed ?? [], [registry]);

  const quickActions = useMemo(
    () => [
      {
        icon: Play,
        label: 'Launch Security Scan',
        description: 'Start a new security testing run with plugins',
        route: '/runs/composer',
        color: 'text-purple-500',
        gradient: 'from-purple-500 to-pink-500'
      },
      {
        icon: Activity,
        label: 'Monitor Live Traffic',
        description: 'View and analyze HTTP/HTTPS flows in real-time',
        route: '/flows',
        color: 'text-blue-500',
        gradient: 'from-blue-500 to-cyan-500'
      },
      {
        icon: Shield,
        label: 'Review Findings',
        description: 'Investigate security cases and vulnerabilities',
        route: '/cases',
        color: 'text-rose-500',
        gradient: 'from-rose-500 to-pink-500'
      },
      {
        icon: Lock,
        label: 'Cipher Analysis',
        description: 'Decode and analyze encrypted data',
        route: '/cipher',
        color: 'text-violet-500',
        gradient: 'from-violet-500 to-purple-500'
      },
      {
        icon: TrendingUp,
        label: 'Entropy Testing',
        description: 'Analyze randomness quality of tokens',
        route: '/entropy',
        color: 'text-emerald-500',
        gradient: 'from-emerald-500 to-teal-500'
      },
      {
        icon: Zap,
        label: 'Blitz Fuzzing',
        description: 'High-speed fuzzing and mutation testing',
        route: '/blitz',
        color: 'text-orange-500',
        gradient: 'from-orange-500 to-red-500'
      },
      {
        icon: Code,
        label: 'Request Rewriting',
        description: 'Modify requests and responses on the fly',
        route: '/rewrite',
        color: 'text-cyan-500',
        gradient: 'from-cyan-500 to-blue-500'
      },
      {
        icon: Target,
        label: 'Scope Management',
        description: 'Define and manage testing boundaries',
        route: '/scope',
        color: 'text-indigo-500',
        gradient: 'from-indigo-500 to-purple-500'
      },
      {
        icon: Puzzle,
        label: 'Plugin Marketplace',
        description: 'Discover and install security plugins',
        route: '/plugins',
        color: 'text-amber-500',
        gradient: 'from-amber-500 to-orange-500'
      }
    ],
    []
  );

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-8 p-8">
      {/* Header */}
      <section className="space-y-3">
        <div className="flex items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-purple-500 via-pink-500 to-rose-500 shadow-lg">
            <Layers className="h-7 w-7 text-white" strokeWidth={2} />
          </div>
          <div>
            <h1 className="text-3xl font-semibold tracking-tight">Control Center</h1>
            <p className="text-muted-foreground">
              Unified access to all security testing plugins and features
            </p>
          </div>
        </div>
      </section>

      {/* Pipeline Visualization */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold">Security Testing Pipeline</h2>
          <p className="text-sm text-muted-foreground">
            Visual overview of how data flows through the 0xGen platform
          </p>
        </div>
        <div className="rounded-2xl border border-border/70 bg-card/95 p-8 shadow-soft backdrop-blur-sm">
          <PipelineFlow />
        </div>
      </section>

      {/* Quick Actions Grid */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold">Quick Actions</h2>
            <p className="text-sm text-muted-foreground">
              Jump directly to any major feature or workflow
            </p>
          </div>
        </div>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {quickActions.map((action, idx) => (
            <QuickAction key={idx} {...action} />
          ))}
        </div>
      </section>

      {/* Installed Plugins Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold">Installed Plugins</h2>
            <p className="text-sm text-muted-foreground">
              {installedPlugins.length} plugin{installedPlugins.length !== 1 ? 's' : ''} ready for
              security testing
            </p>
          </div>
          <Button variant="outline" onClick={() => void refresh()} disabled={loading}>
            {loading ? 'Loading...' : 'Refresh'}
          </Button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center rounded-2xl border border-border/70 bg-muted/40 p-12">
            <div className="flex flex-col items-center gap-3">
              <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
              <p className="text-sm text-muted-foreground">Loading plugins...</p>
            </div>
          </div>
        ) : error ? (
          <div className="rounded-2xl border border-destructive/40 bg-destructive/10 p-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <div>
                <p className="font-medium text-destructive">Failed to load plugin registry</p>
                <p className="mt-1 text-sm text-destructive/80">{error}</p>
              </div>
            </div>
          </div>
        ) : installedPlugins.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-4 rounded-2xl border border-border/70 bg-muted/40 p-12">
            <Puzzle className="h-12 w-12 text-muted-foreground/50" />
            <div className="text-center">
              <p className="font-medium text-foreground">No plugins installed</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Visit the marketplace to install security testing plugins
              </p>
            </div>
            <Button
              onClick={() => window.location.href = '/plugins'}
              className="mt-2"
            >
              Browse Marketplace
            </Button>
          </div>
        ) : (
          <div className="grid gap-6 lg:grid-cols-2">
            {installedPlugins.map((plugin, idx) => (
              <PluginCard key={plugin.id} plugin={plugin} index={idx} />
            ))}
          </div>
        )}
      </section>

      {/* System Status */}
      <section className="space-y-4">
        <h2 className="text-xl font-semibold">System Status</h2>
        <div className="grid gap-4 sm:grid-cols-3">
          <div className="flex items-center gap-4 rounded-xl border border-border/70 bg-card/95 p-4 shadow-soft">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10">
              <CheckCircle2 className="h-5 w-5 text-emerald-500" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Plugin System</p>
              <p className="text-lg font-semibold text-foreground">Operational</p>
            </div>
          </div>
          <div className="flex items-center gap-4 rounded-xl border border-border/70 bg-card/95 p-4 shadow-soft">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10">
              <Database className="h-5 w-5 text-blue-500" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">Active Plugins</p>
              <p className="text-lg font-semibold text-foreground">{installedPlugins.length}</p>
            </div>
          </div>
          <div className="flex items-center gap-4 rounded-xl border border-border/70 bg-card/95 p-4 shadow-soft">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-violet-500/10">
              <Sparkles className="h-5 w-5 text-violet-500" />
            </div>
            <div>
              <p className="text-sm font-medium text-muted-foreground">API Version</p>
              <p className="text-lg font-semibold text-foreground">{registry?.daemonVersion ?? 'Unknown'}</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}

export const Route = createFileRoute('/control-center')({
  component: ControlCenterRoute
});

export default ControlCenterRoute;
