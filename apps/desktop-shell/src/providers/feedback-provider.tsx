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

import { FeedbackPanel } from '../components/feedback-panel';
import { useCommandCenter } from './command-center';

interface FeedbackContextValue {
  open: () => void;
  close: () => void;
  isOpen: boolean;
}

const FeedbackContext = createContext<FeedbackContextValue | null>(null);

export function FeedbackProvider({ children }: PropsWithChildren) {
  const [isOpen, setOpen] = useState(false);
  const open = useCallback(() => setOpen(true), []);
  const close = useCallback(() => setOpen(false), []);
  const { registerCommand } = useCommandCenter();

  useEffect(() => {
    const unregister = registerCommand({
      id: 'system.feedback',
      title: 'Send feedback',
      group: 'Support',
      keywords: ['support', 'feedback', 'bug'],
      shortcut: ['mod+shift+f'],
      run: () => setOpen(true),
      closeOnRun: true,
    });
    return () => {
      unregister();
    };
  }, [registerCommand]);

  const value = useMemo<FeedbackContextValue>(
    () => ({ open, close, isOpen }),
    [close, isOpen, open],
  );

  return (
    <FeedbackContext.Provider value={value}>
      {children}
      <AnimatePresence>{isOpen ? <FeedbackPanel open={isOpen} onClose={close} /> : null}</AnimatePresence>
    </FeedbackContext.Provider>
  );
}

export function useFeedback() {
  const context = useContext(FeedbackContext);
  if (!context) {
    throw new Error('useFeedback must be used within a FeedbackProvider');
  }
  return context;
}
