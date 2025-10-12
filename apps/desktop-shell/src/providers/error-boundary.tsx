import { Component, type ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { toast } from 'sonner';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error?: Error;
}

export class AppErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    console.error('Unhandled error boundary exception', error);
    toast.error(error.message ?? 'An unexpected error occurred');
    void invoke('report_renderer_crash', {
      message: error.message ?? 'Unhandled renderer error',
      stack: error.stack ?? null,
    }).catch((invokeError) => {
      console.error('Failed to report renderer crash', invokeError);
    });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-2">
          <h1 className="text-2xl font-semibold">Something went wrong.</h1>
          {this.state.error?.message && (
            <p className="text-muted-foreground">{this.state.error.message}</p>
          )}
        </div>
      );
    }

    return this.props.children;
  }
}
