import { AnimatePresence } from 'framer-motion';
import {
  PropsWithChildren,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import { AboutDialog } from '../components/about-dialog';
import { useCommandCenter } from './command-center';

type AboutContextValue = {
  open: () => void;
  close: () => void;
  isOpen: boolean;
};

const AboutContext = createContext<AboutContextValue | null>(null);

export function AboutProvider({ children }: PropsWithChildren) {
  const [isOpen, setIsOpen] = useState(false);
  const open = useCallback(() => setIsOpen(true), []);
  const close = useCallback(() => setIsOpen(false), []);
  const { registerCommand } = useCommandCenter();

  useEffect(() => {
    const unregister = registerCommand({
      id: 'system.about',
      title: 'About 0xgen',
      group: 'System',
      keywords: ['about', 'version', 'build'],
      run: open,
      closeOnRun: true,
    });
    return () => {
      unregister();
    };
  }, [open, registerCommand]);

  const value = useMemo<AboutContextValue>(() => ({ open, close, isOpen }), [open, close, isOpen]);

  return (
    <AboutContext.Provider value={value}>
      {children}
      <AnimatePresence>{isOpen ? <AboutDialog open={isOpen} onClose={close} /> : null}</AnimatePresence>
    </AboutContext.Provider>
  );
}

export function useAbout() {
  const context = useContext(AboutContext);
  if (!context) {
    throw new Error('useAbout must be used within an AboutProvider');
  }
  return context;
}
