declare module 'mermaid' {
  export interface MermaidConfig {
    startOnLoad?: boolean;
    securityLevel?: 'strict' | 'loose' | 'antiscript' | 'sandbox';
    theme?: string;
  }

  export interface RenderResult {
    svg: string;
    bindFunctions?: (element: Element) => void;
  }

  export function initialize(config: MermaidConfig): void;
  export function render(id: string, text: string, container?: Element): Promise<RenderResult>;

  const mermaid: {
    initialize: typeof initialize;
    render: typeof render;
  };

  export default mermaid;
}
