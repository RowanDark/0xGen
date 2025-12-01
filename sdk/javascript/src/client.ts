import {
  ClientConfig,
  CreateScanRequest,
  CreateScanResponse,
  Scan,
  ScanResult,
  ListPluginsResponse,
  TokenRequest,
  TokenResponse,
  APIError,
  CipherExecuteRequest,
  CipherExecuteResponse,
  CipherRecipeSaveRequest,
  CipherRecipe,
} from './types';

/**
 * Custom error class for API errors
 */
export class OxGenAPIError extends Error implements APIError {
  status: number;
  details?: any;

  constructor(message: string, status: number, details?: any) {
    super(message);
    this.name = 'OxGenAPIError';
    this.status = status;
    this.details = details;
    // Maintains proper stack trace for where our error was thrown
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, OxGenAPIError);
    }
  }
}

/**
 * Main API client for 0xGen Security Scanner
 */
export class OxGenClient {
  private baseURL: string;
  private apiKey?: string;
  private staticToken?: string;
  private timeout: number;
  private headers: Record<string, string>;

  /**
   * Creates a new 0xGen API client
   * @param config - Client configuration options
   */
  constructor(config: ClientConfig) {
    this.baseURL = config.baseURL.replace(/\/$/, ''); // Remove trailing slash
    this.apiKey = config.apiKey;
    this.staticToken = config.staticToken;
    this.timeout = config.timeout || 30000;
    this.headers = config.headers || {};
  }

  /**
   * Makes an HTTP request to the API with proper error handling
   * @private
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...this.headers,
        ...((options.headers as Record<string, string>) || {}),
      };

      // Add authentication if available
      if (this.apiKey) {
        headers['Authorization'] = `Bearer ${this.apiKey}`;
      }

      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Handle non-OK responses
      if (!response.ok) {
        let errorMessage = `API Error: ${response.status} ${response.statusText}`;
        let errorDetails;

        try {
          const errorBody = await response.json();
          if (errorBody.message) {
            errorMessage = errorBody.message;
          }
          errorDetails = errorBody;
        } catch {
          // If response body is not JSON, try to get text
          try {
            errorMessage = await response.text();
          } catch {
            // Ignore
          }
        }

        throw new OxGenAPIError(errorMessage, response.status, errorDetails);
      }

      // Parse successful response
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }

      // Return empty object for non-JSON responses
      return {} as T;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof OxGenAPIError) {
        throw error;
      }

      if ((error as any).name === 'AbortError') {
        throw new OxGenAPIError(
          `Request timeout after ${this.timeout}ms`,
          408
        );
      }

      throw new OxGenAPIError(
        `Network error: ${(error as Error).message}`,
        0,
        error
      );
    }
  }

  /**
   * Issue a new API token
   * @param staticToken - Static management token
   * @param request - Token request parameters
   * @returns Token response with JWT and expiration
   */
  async issueToken(
    staticToken: string,
    request: TokenRequest
  ): Promise<TokenResponse> {
    return this.request<TokenResponse>('/api/v1/api-tokens', {
      method: 'POST',
      headers: {
        'X-0xgen-Token': staticToken,
      },
      body: JSON.stringify(request),
    });
  }

  /**
   * List all available plugins
   * @returns List of plugins
   */
  async listPlugins(): Promise<ListPluginsResponse> {
    return this.request<ListPluginsResponse>('/api/v1/plugins', {
      method: 'GET',
    });
  }

  /**
   * Create a new scan
   * @param request - Scan creation parameters
   * @returns Created scan information
   */
  async createScan(request: CreateScanRequest): Promise<CreateScanResponse> {
    return this.request<CreateScanResponse>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * Get scan status and details
   * @param scanId - Scan identifier
   * @returns Detailed scan information
   */
  async getScanStatus(scanId: string): Promise<Scan> {
    return this.request<Scan>(`/api/v1/scans/${scanId}`, {
      method: 'GET',
    });
  }

  /**
   * Get scan results including findings
   * @param scanId - Scan identifier
   * @returns Scan results with findings
   */
  async getScanResults(scanId: string): Promise<ScanResult> {
    return this.request<ScanResult>(`/api/v1/scans/${scanId}/results`, {
      method: 'GET',
    });
  }

  /**
   * Execute a cipher operation
   * @param request - Cipher operation parameters
   * @returns Operation result
   */
  async executeCipher(
    request: CipherExecuteRequest
  ): Promise<CipherExecuteResponse> {
    return this.request<CipherExecuteResponse>('/api/v1/cipher/execute', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * Execute a cipher pipeline
   * @param operations - Array of operations to execute
   * @returns Pipeline result
   */
  async executeCipherPipeline(operations: any[]): Promise<CipherExecuteResponse> {
    return this.request<CipherExecuteResponse>('/api/v1/cipher/pipeline', {
      method: 'POST',
      body: JSON.stringify({ operations }),
    });
  }

  /**
   * Detect cipher/encoding operations
   * @param input - Input data to analyze
   * @returns Detection results
   */
  async detectCipher(input: string): Promise<any> {
    return this.request<any>('/api/v1/cipher/detect', {
      method: 'POST',
      body: JSON.stringify({ input }),
    });
  }

  /**
   * Smart decode - automatically detect and decode input
   * @param input - Input data to decode
   * @returns Decoded result
   */
  async smartDecode(input: string): Promise<CipherExecuteResponse> {
    return this.request<CipherExecuteResponse>('/api/v1/cipher/smart-decode', {
      method: 'POST',
      body: JSON.stringify({ input }),
    });
  }

  /**
   * List available cipher operations
   * @returns List of operations
   */
  async listCipherOperations(): Promise<any> {
    return this.request<any>('/api/v1/cipher/operations', {
      method: 'GET',
    });
  }

  /**
   * Save a cipher recipe
   * @param request - Recipe to save
   * @returns Save confirmation
   */
  async saveCipherRecipe(request: CipherRecipeSaveRequest): Promise<any> {
    return this.request<any>('/api/v1/cipher/recipes/save', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  /**
   * List saved cipher recipes
   * @returns List of recipes
   */
  async listCipherRecipes(): Promise<CipherRecipe[]> {
    const response = await this.request<{ recipes: CipherRecipe[] }>(
      '/api/v1/cipher/recipes/list',
      {
        method: 'GET',
      }
    );
    return response.recipes || [];
  }

  /**
   * Load a cipher recipe
   * @param name - Recipe name
   * @returns Recipe data
   */
  async loadCipherRecipe(name: string): Promise<CipherRecipe> {
    return this.request<CipherRecipe>(
      `/api/v1/cipher/recipes/load?name=${encodeURIComponent(name)}`,
      {
        method: 'GET',
      }
    );
  }

  /**
   * Delete a cipher recipe
   * @param name - Recipe name
   * @returns Deletion confirmation
   */
  async deleteCipherRecipe(name: string): Promise<any> {
    return this.request<any>(
      `/api/v1/cipher/recipes/delete?name=${encodeURIComponent(name)}`,
      {
        method: 'DELETE',
      }
    );
  }

  /**
   * Health check endpoint
   * @returns Health status
   */
  async healthCheck(): Promise<string> {
    const response = await fetch(`${this.baseURL}/healthz`);
    if (!response.ok) {
      throw new OxGenAPIError('Health check failed', response.status);
    }
    return response.text();
  }
}
