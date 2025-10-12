export interface CrashFileMetadata {
  path: string;
  bytes: number;
  description: string;
}

export interface CrashReason {
  kind: string;
  message: string;
  stack?: string;
  location?: string;
}

export interface CrashBundleSummary {
  id: string;
  createdAt: string;
  directory: string;
  reason: CrashReason;
  files: CrashFileMetadata[];
}

export interface CrashFilePreview {
  path: string;
  content: string;
  truncated: boolean;
}
