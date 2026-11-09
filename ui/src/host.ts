// The connection to the MCP Apps host: theme, style variables and fonts from
// the host, and the tool result that the view renders. After simkl-mcp's
// ui/src/host.ts.

import {
  App,
  applyDocumentTheme,
  applyHostFonts,
  applyHostStyleVariables,
  type McpUiHostContext,
} from "@modelcontextprotocol/ext-apps";
import type { GetSubjectsOutput } from "./output";
import "./style.css";

/** What a view asks of the host. The preview page supplies its own. */
export interface Host {
  openLink(url: string): void;
  /** Calls get_subject_by_id, so a view can open a related subject in place. */
  getSubject(id: number): Promise<GetSubjectsOutput>;
}

export type Render<T> = (root: HTMLElement, host: Host, output: T) => void;

/** Connects to the host and renders each tool result into `#app`. */
export async function connect<T>(name: string, render: Render<T>): Promise<App> {
  const root = document.getElementById("app")!;
  const app = new App({ name, version: "1.0.0" });
  const host: Host = {
    openLink: (url) => void app.openLink({ url }),
    getSubject: async (id) => {
      const result = await app.callServerTool({ name: "get_subject_by_id", arguments: { subject_id: id } });
      if (result.isError || !result.structuredContent) throw new Error(`could not load subject ${id}`);
      return result.structuredContent as unknown as GetSubjectsOutput;
    },
  };
  app.onhostcontextchanged = applyContext;
  app.ontoolresult = ({ structuredContent, isError }) => {
    if (isError || !structuredContent) return;
    render(root, host, structuredContent as T);
  };
  await app.connect();
  applyContext(app.getHostContext() ?? {});
  return app;
}

function applyContext(context: McpUiHostContext) {
  if (context.theme) applyDocumentTheme(context.theme);
  if (context.styles?.variables) applyHostStyleVariables(context.styles.variables);
  if (context.styles?.css?.fonts) applyHostFonts(context.styles.css.fonts);
}

/** Builds an element. Children are text or elements; text is never parsed as HTML. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  ...children: (Node | string | null | undefined | false)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { class: className, ...rest } = props;
  if (className) node.className = className;
  Object.assign(node, rest);
  for (const child of children) {
    if (child) node.append(child);
  }
  return node;
}
