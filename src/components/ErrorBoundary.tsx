import React from 'react';
import { ShieldAlert, RotateCcw } from 'lucide-react';

interface ErrorBoundaryState {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return {
      hasError: true,
      message: error.message || 'An unexpected error occurred in the console.',
    };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#080C14] text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-[#0F1623] border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-3 text-rose-400">
              <ShieldAlert className="w-6 h-6 shrink-0" />
              <h1 className="text-lg font-semibold">Console Recovery</h1>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed break-words">
              {this.state.message}
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 min-h-[44px] px-4 py-2 rounded-lg bg-slate-100 text-slate-900 text-sm font-medium hover:bg-white transition-colors"
            >
              <RotateCcw className="w-4 h-4" />
              Reload Console
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
