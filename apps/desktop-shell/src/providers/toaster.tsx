import { Toaster as SonnerToaster } from 'sonner';

export function Toaster() {
  return (
    <SonnerToaster
      richColors
      position="top-right"
      toastOptions={{
        classNames: {
          toast: 'bg-popover text-popover-foreground border border-border shadow-lg'
        }
      }}
    />
  );
}
