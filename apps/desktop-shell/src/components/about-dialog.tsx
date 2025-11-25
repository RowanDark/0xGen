import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { getName, getVersion } from '@tauri-apps/api/app';
import { arch as getArch, platform as getPlatform } from '@tauri-apps/plugin-os';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { ExternalLink, ShieldCheck, Loader2, X } from 'lucide-react';

import { Button } from './ui/button';
import { StatusChip } from './ui/status-chip';

const OWNER = 'RowanDark';
const REPO = '0xgen';
const REPOSITORY = `${OWNER}/${REPO}`;

const REQUEST_HEADERS = {
  Accept: 'application/vnd.github+json',
  'User-Agent': '0xgen-desktop-shell',
};

type VerificationState =
  | { status: 'idle'; message?: string }
  | { status: 'checking' }
  | { status: 'verified'; provenanceUrl: string; releaseUrl: string; sbomUrl?: string }
  | { status: 'unverified'; releaseUrl?: string; message: string; sbomUrl?: string }
  | { status: 'error'; message: string; releaseUrl?: string };

function formatPlatform(value: string): { id: string; label: string } {
  switch (value) {
    case 'win32':
      return { id: 'windows', label: 'Windows' };
    case 'darwin':
      return { id: 'darwin', label: 'macOS' };
    case 'linux':
      return { id: 'linux', label: 'Linux' };
    default:
      return { id: value, label: value };
  }
}

function formatArch(value: string): { id: string; label: string } {
  switch (value) {
    case 'x86_64':
      return { id: 'amd64', label: '64-bit (x86_64)' };
    case 'aarch64':
      return { id: 'arm64', label: '64-bit (ARM)' };
    case 'x86':
      return { id: '386', label: '32-bit (x86)' };
    default:
      return { id: value, label: value };
  }
}

function normaliseTag(version: string): string {
  const trimmed = version.trim();
  if (!trimmed) {
    return '';
  }
  return trimmed.startsWith('v') ? trimmed : `v${trimmed}`;
}

type ReleaseAsset = {
  name: string;
  browser_download_url: string;
};

type ReleaseResponse = {
  assets: ReleaseAsset[];
  html_url: string;
};

async function fetchRelease(tag: string, signal: AbortSignal): Promise<ReleaseResponse | null> {
  const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/releases/tags/${tag}`, {
    method: 'GET',
    headers: REQUEST_HEADERS,
    signal,
  });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return (await response.json()) as ReleaseResponse;
}

function buildArtifactName(tag: string, platform: string, arch: string): string {
  const extension = platform === 'windows' ? 'zip' : 'tar.gz';
  return `0xgenctl_${tag}_${platform}_${arch}.${extension}`;
}

type AboutDialogProps = {
  open: boolean;
  onClose: () => void;
};

export function AboutDialog({ open, onClose }: AboutDialogProps) {
  const [appName, setAppName] = useState('0xgen');
  const [version, setVersion] = useState('');
  const [tag, setTag] = useState('');
  const [platformInfo, setPlatformInfo] = useState<{ id: string; label: string }>({ id: '', label: '' });
  const [archInfo, setArchInfo] = useState<{ id: string; label: string }>({ id: '', label: '' });
  const [verification, setVerification] = useState<VerificationState>({ status: 'idle' });

  useEffect(() => {
    if (!open) {
      return;
    }
    let cancelled = false;
    setVerification((previous) => (previous.status === 'verified' ? previous : { status: 'checking' }));
    void (async () => {
      try {
        const [resolvedName, resolvedVersion, platformValue, archValue] = await Promise.all([
          getName(),
          getVersion(),
          getPlatform(),
          getArch(),
        ]);
        if (cancelled) {
          return;
        }
        const platform = formatPlatform(platformValue);
        const arch = formatArch(archValue);
        setAppName(resolvedName);
        setVersion(resolvedVersion);
        setPlatformInfo(platform);
        setArchInfo(arch);
        setTag(normaliseTag(resolvedVersion));
      } catch (error) {
        if (!cancelled) {
          setVerification({ status: 'error', message: 'Unable to determine application metadata.' });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const currentTag = tag || '';
    if (!currentTag) {
      return;
    }
    if (currentTag.toLowerCase() === 'vdev' || currentTag.toLowerCase() === 'dev') {
      setVerification({ status: 'unverified', message: 'Development builds are not covered by provenance attestations.' });
      return;
    }
    const controller = new AbortController();
    setVerification({ status: 'checking' });
    void fetchRelease(currentTag, controller.signal)
      .then((release) => {
        if (!release) {
          setVerification({
            status: 'unverified',
            message: 'Release provenance has not been published yet.',
          });
          return;
        }
        const provenanceName = `0xgen-${currentTag}-provenance.intoto.jsonl`;
        const sbomName = `0xgen-${currentTag}-sbom.spdx.json`;
        const provenanceAsset = release.assets.find((asset) => asset.name === provenanceName);
        const sbomAsset = release.assets.find((asset) => asset.name === sbomName);
        if (!provenanceAsset) {
          setVerification({
            status: 'unverified',
            releaseUrl: release.html_url,
            message: 'Provenance attestation was not found for this release yet.',
            sbomUrl: sbomAsset?.browser_download_url,
          });
          return;
        }
        setVerification({
          status: 'verified',
          releaseUrl: release.html_url,
          provenanceUrl: provenanceAsset.browser_download_url,
          sbomUrl: sbomAsset?.browser_download_url,
        });
      })
      .catch((error: unknown) => {
        const details = error instanceof Error ? error.message : String(error);
        setVerification({ status: 'error', message: `Unable to query release metadata: ${details}` });
      });
    return () => {
      controller.abort();
    };
  }, [open, tag]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [onClose, open]);

  const artifactFile = useMemo(() => {
    if (!tag || !platformInfo.id || !archInfo.id) {
      return '';
    }
    return buildArtifactName(tag, platformInfo.id, archInfo.id);
  }, [archInfo.id, platformInfo.id, tag]);

  const verifyCommand = useMemo(() => {
    if (!artifactFile || !tag) {
      return '';
    }
    return `0xgenctl verify-build --tag ${tag} --artifact ~/Downloads/${artifactFile}`;
  }, [artifactFile, tag]);

  const renderVerification = () => {
    switch (verification.status) {
      case 'verified':
        return (
          <div className="flex flex-col gap-2">
            <StatusChip status="Verified build" tone="success" className="w-fit" />
            <p className="text-sm text-muted-foreground">
              This build was attested with Sigstore. Download the provenance bundle and run the CLI verification command to
              reproduce the check locally.
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                variant="secondary"
                onClick={() => {
                  void openExternal(verification.provenanceUrl);
                }}
              >
                <ShieldCheck className="mr-2 h-4 w-4" /> View provenance
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  void openExternal(verification.releaseUrl);
                }}
              >
                <ExternalLink className="mr-2 h-4 w-4" /> Release page
              </Button>
              {verification.sbomUrl ? (
                <Button
                  variant="ghost"
                  onClick={() => {
                    void openExternal(verification.sbomUrl!);
                  }}
                >
                  <ExternalLink className="mr-2 h-4 w-4" /> Download SBOM
                </Button>
              ) : null}
            </div>
          </div>
        );
      case 'checking':
        return (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" /> Checking release provenance…
          </div>
        );
      case 'unverified':
        return (
          <div className="flex flex-col gap-2">
            <StatusChip status="Provenance unavailable" tone="warning" className="w-fit" />
            <p className="text-sm text-muted-foreground">{verification.message}</p>
            <div className="flex flex-wrap gap-2">
              {verification.releaseUrl ? (
                <Button
                  variant="outline"
                  onClick={() => {
                    void openExternal(verification.releaseUrl!);
                  }}
                >
                  <ExternalLink className="mr-2 h-4 w-4" /> Release page
                </Button>
              ) : null}
              {verification.sbomUrl ? (
                <Button
                  variant="ghost"
                  onClick={() => {
                    void openExternal(verification.sbomUrl!);
                  }}
                >
                  <ExternalLink className="mr-2 h-4 w-4" /> Download SBOM
                </Button>
              ) : null}
            </div>
          </div>
        );
      case 'error':
        return (
          <div className="flex flex-col gap-2">
            <StatusChip status="Verification failed" tone="critical" className="w-fit" />
            <p className="text-sm text-muted-foreground">{verification.message}</p>
            {verification.releaseUrl ? (
              <Button
                variant="outline"
                onClick={() => {
                  void openExternal(verification.releaseUrl!);
                }}
              >
                <ExternalLink className="mr-2 h-4 w-4" /> Release page
              </Button>
            ) : null}
          </div>
        );
      default:
        return null;
    }
  };

  if (!open) {
    return null;
  }

  return (
    <motion.div
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
    >
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-labelledby="about-dialog-title"
        tabIndex={-1}
        className="mx-4 w-full max-w-2xl rounded-lg border border-border bg-background p-6 shadow-xl"
        initial={{ y: 24, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: 24, opacity: 0 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      >
        <header className="mb-6 flex items-start justify-between gap-3">
          <div>
            <h2 id="about-dialog-title" className="text-2xl font-semibold">
              About {appName}
            </h2>
            <p className="text-sm text-muted-foreground">Inspect runtime details for this installation and review the release provenance generated by the Sigstore pipeline.</p>
          </div>
          <Button type="button" variant="ghost" size="icon" onClick={onClose}>
            <X className="h-4 w-4" aria-hidden="true" />
            <span className="sr-only">Close about window</span>
          </Button>
        </header>

        <section className="grid gap-6 md:grid-cols-2">
          <div className="space-y-3">
            <div>
              <h3 className="text-sm font-medium text-muted-foreground">Version</h3>
              <p className="text-base font-semibold text-foreground">{version || 'Unknown'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground">Release tag</h3>
              <p className="text-base text-foreground">{tag || 'Not available'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground">Platform</h3>
              <p className="text-base text-foreground">
                {platformInfo.label || 'Unknown'} {archInfo.label ? `• ${archInfo.label}` : null}
              </p>
            </div>
            {artifactFile ? (
              <div>
                <h3 className="text-sm font-medium text-muted-foreground">Default artifact</h3>
                <p className="font-mono text-sm text-foreground break-all">{artifactFile}</p>
              </div>
            ) : null}
          </div>

          <div className="space-y-4">
            <h3 className="text-sm font-semibold text-foreground">Build provenance</h3>
            {renderVerification()}
          </div>
        </section>

        {verifyCommand ? (
          <section className="mt-6 space-y-2">
            <h3 className="text-sm font-semibold text-foreground">Verify locally</h3>
            <p className="text-sm text-muted-foreground">
              Use the CLI to validate the provenance bundle after downloading the release artifact:
            </p>
            <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs text-muted-foreground">
              <code>{verifyCommand}</code>
            </pre>
          </section>
        ) : null}
      </motion.div>
    </motion.div>
  );
}
