import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';

import { type ThemeName, useTheme } from './theme-provider';

export type ModeName = 'red' | 'blue' | 'purple';

export type ModeAction = {
  id: string;
  label: string;
  to: string;
  icon: LucideIcon;
  variant?: 'default' | 'secondary' | 'outline';
  className?: string;
};

export type ModeModule = {
  id: string;
  name: string;
  focus: string;
  description: string;
  to: string;
  icon: LucideIcon;
  badgeClass: string;
  iconClass: string;
};

export type ModeConfiguration = {
  value: ModeName;
  label: string;
  shortLabel: string;
  description: string;
  theme: ThemeName;
  icon: LucideIcon;
  accentGradient: string;
  switcherActiveClass: string;
  switcherIconClass: string;
  actions: ModeAction[];
  modules: ModeModule[];
};

type ModeContextValue = {
  mode: ModeName;
  setMode: (mode: ModeName) => void;
  options: readonly ModeConfiguration[];
  config: ModeConfiguration;
};

const MODE_STORAGE_KEY = '0xgen.mode.presets';
const DEFAULT_MODE: ModeName = 'purple';

function isModeName(value: unknown): value is ModeName {
  return value === 'red' || value === 'blue' || value === 'purple';
}

const ModeContext = createContext<ModeContextValue | undefined>(undefined);

function getStoredMode(): ModeName {
  if (typeof window === 'undefined') {
    return DEFAULT_MODE;
  }
  try {
    const stored = window.localStorage.getItem(MODE_STORAGE_KEY);
    if (isModeName(stored)) {
      return stored;
    }
  } catch (error) {
    console.warn('Unable to read stored mode preference', error);
  }
  return DEFAULT_MODE;
}

export function ModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ModeName>(() => getStoredMode());
  const { setTheme } = useTheme();

  useEffect(() => {
    const config = MODE_CONFIG_MAP[mode];
    setTheme(config.theme);
    if (typeof window !== 'undefined') {
      try {
        window.localStorage.setItem(MODE_STORAGE_KEY, mode);
      } catch (error) {
        console.warn('Unable to persist mode preference', error);
      }
    }
  }, [mode, setTheme]);

  const handleSetMode = useCallback((nextMode: ModeName) => {
    setModeState((current) => {
      if (current === nextMode) {
        return current;
      }
      return nextMode;
    });
  }, []);

  const value = useMemo<ModeContextValue>(
    () => ({
      mode,
      setMode: handleSetMode,
      options: MODE_OPTIONS,
      config: MODE_CONFIG_MAP[mode]
    }),
    [handleSetMode, mode]
  );

  return <ModeContext.Provider value={value}>{children}</ModeContext.Provider>;
}

export function useMode() {
  const context = useContext(ModeContext);
  if (!context) {
    throw new Error('useMode must be used within a ModeProvider');
  }
  return context;
}

// --- Mode configuration map -------------------------------------------------

import {
  Activity,
  Bell,
  Flame,
  FlaskConical,
  GitMerge,
  Grid,
  Play,
  Radar,
  Share2,
  ShieldCheck,
  Sparkles,
  Swords,
  Workflow
} from 'lucide-react';

const MODE_OPTIONS = [
  {
    value: 'red',
    label: 'Red team mode',
    shortLabel: 'Red',
    description: 'Offensive operations with aggressive tooling front and center.',
    theme: 'red',
    icon: Flame,
    accentGradient: 'from-rose-500/90 via-red-500/85 to-orange-500/85',
    switcherActiveClass:
      'bg-gradient-to-r from-rose-500/90 via-red-500/90 to-orange-500/90 text-white shadow-lg ring-1 ring-rose-400/50',
    switcherIconClass: 'text-white',
    actions: [
      {
        id: 'launch-run',
        label: 'Launch offensive run',
        to: '/runs/composer',
        icon: Play,
        className:
          'bg-gradient-to-r from-rose-500 via-red-500 to-orange-500 text-white shadow-lg ring-1 ring-rose-400/50 hover:from-rose-500/90 hover:via-red-500/90 hover:to-orange-500/90'
      },
      {
        id: 'inspect-flows',
        label: 'Inspect live traffic',
        to: '/flows',
        icon: Activity,
        variant: 'outline'
      },
      {
        id: 'adjust-scope',
        label: 'Adjust engagement scope',
        to: '/scope',
        icon: Radar,
        variant: 'outline'
      }
    ],
    modules: [
      {
        id: 'campaign-planner',
        name: 'Campaign planner',
        focus: 'Offense',
        description: 'Chain payloads, coordinate operators, and track execution windows.',
        to: '/flows',
        icon: Swords,
        badgeClass: 'bg-rose-500/15 text-rose-200 ring-1 ring-inset ring-rose-500/40',
        iconClass: 'bg-rose-500/20 text-rose-100 shadow-inner ring-1 ring-inset ring-rose-500/50'
      },
      {
        id: 'payload-workshop',
        name: 'Payload workshop',
        focus: 'Payloads',
        description: 'Build, version, and stage payloads with integrated validation.',
        to: '/runs/composer',
        icon: FlaskConical,
        badgeClass: 'bg-orange-500/15 text-orange-200 ring-1 ring-inset ring-orange-500/40',
        iconClass: 'bg-orange-500/20 text-orange-100 shadow-inner ring-1 ring-inset ring-orange-500/50'
      },
      {
        id: 'exfil-ops',
        name: 'Exfil ops center',
        focus: 'C2',
        description: 'Monitor beacons and exfiltration channels in real time.',
        to: '/runs',
        icon: Radar,
        badgeClass: 'bg-amber-500/15 text-amber-100 ring-1 ring-inset ring-amber-500/40',
        iconClass: 'bg-amber-500/20 text-amber-50 shadow-inner ring-1 ring-inset ring-amber-500/50'
      }
    ]
  },
  {
    value: 'blue',
    label: 'Blue team mode',
    shortLabel: 'Blue',
    description: 'Detection engineering and alert response presets ready to go.',
    theme: 'blue',
    icon: ShieldCheck,
    accentGradient: 'from-sky-500/90 via-blue-500/85 to-indigo-500/85',
    switcherActiveClass:
      'bg-gradient-to-r from-sky-500/90 via-blue-500/90 to-indigo-500/90 text-white shadow-lg ring-1 ring-sky-400/50',
    switcherIconClass: 'text-white',
    actions: [
      {
        id: 'open-detections',
        label: 'Review detections',
        to: '/cases',
        icon: ShieldCheck,
        className:
          'bg-gradient-to-r from-sky-500 via-blue-500 to-indigo-500 text-white shadow-lg ring-1 ring-sky-400/50 hover:from-sky-500/90 hover:via-blue-500/90 hover:to-indigo-500/90'
      },
      {
        id: 'monitor-queue',
        label: 'Monitor telemetry queue',
        to: '/flows',
        icon: Activity,
        variant: 'outline'
      },
      {
        id: 'launch-playbook',
        label: 'Launch response playbook',
        to: '/runs/composer',
        icon: Workflow,
        variant: 'outline'
      }
    ],
    modules: [
      {
        id: 'alert-triage',
        name: 'Alert triage desk',
        focus: 'Detections',
        description: 'Prioritise findings, assign analysts, and track containment steps.',
        to: '/cases',
        icon: Bell,
        badgeClass: 'bg-sky-500/15 text-sky-100 ring-1 ring-inset ring-sky-500/40',
        iconClass: 'bg-sky-500/20 text-sky-50 shadow-inner ring-1 ring-inset ring-sky-500/50'
      },
      {
        id: 'queue-guardian',
        name: 'Queue guardian',
        focus: 'Telemetry',
        description: 'Inspect queue depth, drops, and enrichment coverage in one place.',
        to: '/flows',
        icon: Activity,
        badgeClass: 'bg-cyan-500/15 text-cyan-100 ring-1 ring-inset ring-cyan-500/40',
        iconClass: 'bg-cyan-500/20 text-cyan-50 shadow-inner ring-1 ring-inset ring-cyan-500/50'
      },
      {
        id: 'response-playbooks',
        name: 'Response playbooks',
        focus: 'Response',
        description: 'Launch automation to contain incidents and verify recovery.',
        to: '/runs/composer',
        icon: Workflow,
        badgeClass: 'bg-blue-500/15 text-blue-100 ring-1 ring-inset ring-blue-500/40',
        iconClass: 'bg-blue-500/20 text-blue-50 shadow-inner ring-1 ring-inset ring-blue-500/50'
      }
    ]
  },
  {
    value: 'purple',
    label: 'Purple team mode',
    shortLabel: 'Purple',
    description: 'Correlate offensive and defensive insights for joint operations.',
    theme: 'purple',
    icon: Sparkles,
    accentGradient: 'from-fuchsia-500/90 via-purple-500/85 to-indigo-500/85',
    switcherActiveClass:
      'bg-gradient-to-r from-fuchsia-500/90 via-purple-500/90 to-indigo-500/90 text-white shadow-lg ring-1 ring-fuchsia-400/50',
    switcherIconClass: 'text-white',
    actions: [
      {
        id: 'start-correlation',
        label: 'Start correlation workspace',
        to: '/compare',
        icon: GitMerge,
        className:
          'bg-gradient-to-r from-fuchsia-500 via-purple-500 to-indigo-500 text-white shadow-lg ring-1 ring-purple-400/50 hover:from-fuchsia-500/90 hover:via-purple-500/90 hover:to-indigo-500/90'
      },
      {
        id: 'review-campaigns',
        label: 'Review recent campaigns',
        to: '/runs',
        icon: Grid,
        variant: 'outline'
      },
      {
        id: 'sync-intel',
        label: 'Sync intel coverage',
        to: '/scope',
        icon: Share2,
        variant: 'outline'
      }
    ],
    modules: [
      {
        id: 'fusion-correlator',
        name: 'Fusion correlator',
        focus: 'Correlation',
        description: 'Blend adversary telemetry with detection results to surface gaps.',
        to: '/compare',
        icon: GitMerge,
        badgeClass: 'bg-fuchsia-500/15 text-fuchsia-100 ring-1 ring-inset ring-fuchsia-500/40',
        iconClass: 'bg-fuchsia-500/20 text-fuchsia-50 shadow-inner ring-1 ring-inset ring-fuchsia-500/50'
      },
      {
        id: 'campaign-matrix',
        name: 'Campaign coverage matrix',
        focus: 'Matrix',
        description: 'Map offensive steps to defensive coverage across recent activity.',
        to: '/runs',
        icon: Grid,
        badgeClass: 'bg-purple-500/15 text-purple-100 ring-1 ring-inset ring-purple-500/40',
        iconClass: 'bg-purple-500/20 text-purple-50 shadow-inner ring-1 ring-inset ring-purple-500/50'
      },
      {
        id: 'intel-bridge',
        name: 'Intelligence bridge',
        focus: 'Intel',
        description: 'Share discoveries and coverage requests between teams instantly.',
        to: '/scope',
        icon: Share2,
        badgeClass: 'bg-indigo-500/15 text-indigo-100 ring-1 ring-inset ring-indigo-500/40',
        iconClass: 'bg-indigo-500/20 text-indigo-50 shadow-inner ring-1 ring-inset ring-indigo-500/50'
      }
    ]
  }
] as const satisfies readonly ModeConfiguration[];

const MODE_CONFIG_MAP: Record<ModeName, ModeConfiguration> = MODE_OPTIONS.reduce(
  (map, option) => {
    map[option.value] = option;
    return map;
  },
  {
    red: MODE_OPTIONS[0],
    blue: MODE_OPTIONS[1],
    purple: MODE_OPTIONS[2]
  } as Record<ModeName, ModeConfiguration>
);

