import { requireEnv, requireSecret } from "../../util/env";

export interface SamlConfig {
  idpSsoUrl: string;
  idpEntityId: string;
  idpCert: string;
  spEntityId: string;
  spAcsUrl: string;
  sessionSecret: string;
}

export function getSamlConfig(): SamlConfig {
  return {
    idpSsoUrl: requireEnv("IDP_SSO_URL"),
    idpEntityId: requireEnv("IDP_ENTITY_ID"),
    idpCert: requireSecret("IDP_CERT"),
    spEntityId: requireEnv("SP_ENTITY_ID"),
    spAcsUrl: requireEnv("SP_ACS_URL"),
    sessionSecret: requireSecret("SESSION_SECRET"),
  };
}
