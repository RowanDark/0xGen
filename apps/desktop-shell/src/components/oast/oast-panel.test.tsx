import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { OASTPanel } from './oast-panel';
import * as useOASTModule from '../../lib/use-oast';
import type { Interaction, OASTStats, OASTStatus } from '../../lib/use-oast';

// Mock the useOAST hook
vi.mock('../../lib/use-oast', () => ({
  useOAST: vi.fn(),
}));

// Mock framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: any) => <div {...props}>{children}</div>,
  },
  AnimatePresence: ({ children }: any) => <>{children}</>,
}));

describe('OASTPanel', () => {
  const mockRefresh = vi.fn();
  const mockClearInteractions = vi.fn();

  const defaultMockReturn = {
    isEnabled: true,
    status: {
      running: true,
      port: 8443,
      mode: 'local',
    } as OASTStatus,
    interactions: [] as Interaction[],
    stats: {
      total: 0,
      uniqueIDs: 0,
      byType: {},
    } as OASTStats,
    loading: false,
    error: null,
    refresh: mockRefresh,
    clearInteractions: mockClearInteractions,
  };

  beforeEach(() => {
    vi.mocked(useOASTModule.useOAST).mockReturnValue(defaultMockReturn);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows disabled state when OAST is off', () => {
    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      isEnabled: false,
      status: null,
    });

    render(<OASTPanel />);

    expect(screen.getByText('OAST is Disabled')).toBeInTheDocument();
    expect(screen.getByText('Enable OAST to detect blind vulnerabilities')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /enable oast/i })).toBeInTheDocument();
  });

  it('shows running status when enabled', () => {
    render(<OASTPanel />);

    expect(screen.getByText('Running on :8443')).toBeInTheDocument();
  });

  it('displays interactions count in stats', () => {
    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      stats: {
        total: 10,
        uniqueIDs: 5,
        byType: { http: 10 },
      },
    });

    render(<OASTPanel />);

    expect(screen.getByText('10')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
  });

  it('displays empty state when no interactions', () => {
    render(<OASTPanel />);

    expect(screen.getByText('No interactions yet')).toBeInTheDocument();
    expect(screen.getByText('Callbacks will appear here in real-time')).toBeInTheDocument();
  });

  it('displays interactions in list', async () => {
    const mockInteractions: Interaction[] = [
      {
        id: 'test-123-abc',
        timestamp: new Date().toISOString(),
        type: 'http',
        method: 'GET',
        path: '/callback/test-123-abc',
        clientIP: '127.0.0.1',
      },
      {
        id: 'test-456-def',
        timestamp: new Date().toISOString(),
        type: 'http',
        method: 'POST',
        path: '/callback/test-456-def',
        clientIP: '192.168.1.1',
      },
    ];

    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      interactions: mockInteractions,
      stats: {
        total: 2,
        uniqueIDs: 2,
        byType: { http: 2 },
      },
    });

    render(<OASTPanel />);

    expect(screen.getByText(/test-123/)).toBeInTheDocument();
    expect(screen.getByText(/test-456/)).toBeInTheDocument();
    expect(screen.getByText('127.0.0.1')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
  });

  it('shows interaction details on click', async () => {
    const mockInteractions: Interaction[] = [
      {
        id: 'detail-test-123',
        timestamp: new Date().toISOString(),
        type: 'http',
        method: 'GET',
        path: '/callback/detail-test-123',
        clientIP: '127.0.0.1',
        userAgent: 'Mozilla/5.0 Test',
      },
    ];

    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      interactions: mockInteractions,
      stats: {
        total: 1,
        uniqueIDs: 1,
        byType: { http: 1 },
      },
    });

    render(<OASTPanel />);

    // Click on the interaction
    const interactionItem = screen.getByText(/detail-test-123/);
    fireEvent.click(interactionItem);

    // Check that details are shown
    await waitFor(() => {
      expect(screen.getByText('Interaction Details')).toBeInTheDocument();
    });

    expect(screen.getByText('detail-test-123')).toBeInTheDocument();
    expect(screen.getByText('Mozilla/5.0 Test')).toBeInTheDocument();
  });

  it('calls refresh when refresh button is clicked', () => {
    render(<OASTPanel />);

    const refreshButton = screen.getByTitle('Refresh');
    fireEvent.click(refreshButton);

    expect(mockRefresh).toHaveBeenCalled();
  });

  it('shows settings modal when settings button is clicked', async () => {
    render(<OASTPanel />);

    const settingsButton = screen.getByTitle('Settings');
    fireEvent.click(settingsButton);

    await waitFor(() => {
      expect(screen.getByText('OAST Settings')).toBeInTheDocument();
    });
  });

  it('shows loading state on refresh button', () => {
    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      loading: true,
    });

    render(<OASTPanel />);

    const refreshButton = screen.getByTitle('Refresh');
    expect(refreshButton).toBeDisabled();
  });

  it('opens settings modal from disabled state', async () => {
    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      isEnabled: false,
      status: null,
    });

    render(<OASTPanel />);

    const enableButton = screen.getByRole('button', { name: /enable oast/i });
    fireEvent.click(enableButton);

    await waitFor(() => {
      expect(screen.getByText('OAST Settings')).toBeInTheDocument();
    });
  });

  it('displays method badges correctly', () => {
    const mockInteractions: Interaction[] = [
      {
        id: 'method-test-1',
        timestamp: new Date().toISOString(),
        type: 'http',
        method: 'GET',
        path: '/callback/test',
        clientIP: '127.0.0.1',
      },
      {
        id: 'method-test-2',
        timestamp: new Date().toISOString(),
        type: 'http',
        method: 'POST',
        path: '/callback/test',
        clientIP: '127.0.0.1',
      },
    ];

    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      interactions: mockInteractions,
      stats: {
        total: 2,
        uniqueIDs: 2,
        byType: { http: 2 },
      },
    });

    render(<OASTPanel />);

    expect(screen.getByText('GET')).toBeInTheDocument();
    expect(screen.getByText('POST')).toBeInTheDocument();
  });

  it('shows placeholder when no interaction is selected', () => {
    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      ...defaultMockReturn,
      interactions: [
        {
          id: 'test-123',
          timestamp: new Date().toISOString(),
          type: 'http',
          method: 'GET',
          path: '/callback/test',
          clientIP: '127.0.0.1',
        },
      ],
      stats: {
        total: 1,
        uniqueIDs: 1,
        byType: { http: 1 },
      },
    });

    render(<OASTPanel />);

    expect(screen.getByText('Select an interaction to view details')).toBeInTheDocument();
  });
});

describe('InteractionDetail', () => {
  it('allows copying interaction as JSON', async () => {
    const mockInteractions: Interaction[] = [
      {
        id: 'copy-test-123',
        timestamp: new Date().toISOString(),
        type: 'http',
        method: 'GET',
        path: '/callback/copy-test',
        clientIP: '127.0.0.1',
      },
    ];

    vi.mocked(useOASTModule.useOAST).mockReturnValue({
      isEnabled: true,
      status: {
        running: true,
        port: 8443,
        mode: 'local',
      },
      interactions: mockInteractions,
      stats: {
        total: 1,
        uniqueIDs: 1,
        byType: { http: 1 },
      },
      loading: false,
      error: null,
      refresh: vi.fn(),
      clearInteractions: vi.fn(),
    });

    // Mock clipboard API
    const mockWriteText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: mockWriteText,
      },
    });

    render(<OASTPanel />);

    // Click on interaction to show details
    const interactionItem = screen.getByText(/copy-test-123/);
    fireEvent.click(interactionItem);

    // Click copy button
    await waitFor(() => {
      const copyButton = screen.getByText('Copy');
      fireEvent.click(copyButton);
    });

    expect(mockWriteText).toHaveBeenCalled();
  });
});
