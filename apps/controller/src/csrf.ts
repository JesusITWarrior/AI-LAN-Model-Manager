import type { SessionManager } from "./session-manager.js";
export const SAFE_METHODS=Object.freeze(["GET","HEAD","OPTIONS"] as const);
export function requiresCsrf(method:unknown):boolean {return typeof method!=="string"||!SAFE_METHODS.includes(method.toUpperCase() as typeof SAFE_METHODS[number]);}
export function validateCsrf(manager:SessionManager,method:unknown,sessionToken:unknown,headerToken:unknown):boolean {if(!requiresCsrf(method))return manager.authenticate(sessionToken)!==null;return manager.authenticateCsrf(sessionToken,headerToken)!==null;}
