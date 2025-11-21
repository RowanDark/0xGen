import { motion, useReducedMotion } from 'framer-motion';
import { ArrowRight, Database, FileSearch, Network, Shield, Zap } from 'lucide-react';
import { cn } from '../lib/utils';

type PipelineStage = {
  id: string;
  icon: typeof Network;
  label: string;
  description: string;
  color: string;
  gradient: string;
};

const stages: PipelineStage[] = [
  {
    id: 'proxy',
    icon: Network,
    label: 'Proxy',
    description: 'Intercept traffic',
    color: 'text-fuchsia-500',
    gradient: 'from-fuchsia-500 to-pink-500'
  },
  {
    id: 'plugins',
    icon: Zap,
    label: 'Plugins',
    description: 'Process & analyze',
    color: 'text-purple-500',
    gradient: 'from-purple-500 to-pink-500'
  },
  {
    id: 'findings',
    icon: FileSearch,
    label: 'Findings',
    description: 'Detect issues',
    color: 'text-blue-500',
    gradient: 'from-blue-500 to-cyan-500'
  },
  {
    id: 'cases',
    icon: Shield,
    label: 'Cases',
    description: 'Correlate & dedupe',
    color: 'text-rose-500',
    gradient: 'from-rose-500 to-pink-500'
  },
  {
    id: 'storage',
    icon: Database,
    label: 'Storage',
    description: 'Persist results',
    color: 'text-emerald-500',
    gradient: 'from-emerald-500 to-teal-500'
  }
];

export function PipelineFlow() {
  const shouldReduceMotion = useReducedMotion();

  return (
    <div className="relative flex items-center justify-between gap-4 overflow-x-auto pb-4">
      {stages.map((stage, index) => {
        const Icon = stage.icon;
        const isLast = index === stages.length - 1;

        return (
          <div key={stage.id} className="flex items-center gap-4">
            <motion.div
              initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={
                shouldReduceMotion
                  ? { duration: 0 }
                  : {
                      delay: index * 0.1,
                      duration: 0.4,
                      type: 'spring',
                      stiffness: 200,
                      damping: 20
                    }
              }
              className="group relative flex flex-col items-center gap-3"
            >
              {/* Stage Icon */}
              <div
                className={cn(
                  'relative flex h-16 w-16 items-center justify-center rounded-2xl shadow-lg transition-transform group-hover:scale-110',
                  'bg-gradient-to-br',
                  stage.gradient
                )}
              >
                <Icon className="h-8 w-8 text-white" strokeWidth={2} />

                {/* Pulse animation */}
                {!shouldReduceMotion && (
                  <motion.div
                    className={cn(
                      'absolute inset-0 rounded-2xl bg-gradient-to-br',
                      stage.gradient
                    )}
                    initial={{ opacity: 0.6, scale: 1 }}
                    animate={{ opacity: 0, scale: 1.5 }}
                    transition={{
                      duration: 2,
                      repeat: Infinity,
                      repeatDelay: 1,
                      delay: index * 0.2
                    }}
                  />
                )}
              </div>

              {/* Stage Label */}
              <div className="text-center">
                <p className="font-semibold text-foreground">{stage.label}</p>
                <p className="text-xs text-muted-foreground">{stage.description}</p>
              </div>
            </motion.div>

            {/* Arrow between stages */}
            {!isLast && (
              <motion.div
                initial={shouldReduceMotion ? false : { opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={
                  shouldReduceMotion
                    ? { duration: 0 }
                    : {
                        delay: index * 0.1 + 0.2,
                        duration: 0.4
                      }
                }
                className="flex items-center"
              >
                <ArrowRight className="h-6 w-6 text-muted-foreground" strokeWidth={2} />
              </motion.div>
            )}
          </div>
        );
      })}
    </div>
  );
}
