export { createAuthApp } from "./app";
export type { AuthAppOptions } from "./app";
export { ErrorPage } from "./error";
export { Chooser } from "./chooser";
export { resolveRuntimeConfig } from "./config";
export type { RuntimeConfig } from "./config";
export {
  PROVIDER_REGISTRY,
  parseAllowlist,
  selectProviders,
  buildLoginUrl,
} from "./providers/registry";
export type { ProviderDef, ResolvedProvider } from "./providers/registry";
