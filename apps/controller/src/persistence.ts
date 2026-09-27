export {
  CONTROLLER_MIGRATIONS, PersistenceError, migrateControllerDatabase, migrationChecksum, openControllerDatabase,
  type Migration, type OpenControllerDatabaseOptions, type PersistenceErrorCode,
} from "./database.js";
export {
  AuditRepository, JobRepository, JobStoreError, createJobStores,
  type AuditRecord, type CoupledContext, type HistoryRecord, type JobRecord, type JobStores, type JobStoreErrorCode,
} from "./jobs-store.js";
export {
  ControllerRepositories, HostRepository, ModelRepository, ProviderRepository, RepositoryError, createControllerRepositories,
  parseHostRecord, parseModelRecord, parseProviderRecord,
  type HostInventorySnapshot, type HostRecord, type ModelRecord, type ProviderRecord, type ReconcileCounts, type UpsertOutcome,
} from "./repositories.js";
export {
  CredentialError, DUMMY_CREDENTIAL, PASSWORD_MIN_BYTES, PASSWORD_MAX_BYTES, SCRYPT_N, SCRYPT_R, SCRYPT_P,
  SCRYPT_KEY_LENGTH, SCRYPT_SALT_BYTES, SCRYPT_MAX_N, SCRYPT_MAX_R, SCRYPT_MAX_P, SCRYPT_MAX_KEY_LENGTH,
  encodeCredential, parseCredential, hashPassword, verifyCredential, validatePassword, normalizeUsername,
  type CredentialErrorCode, type ParsedCredential, type PasswordCryptoEngine, type ScryptParameters,
} from "./credentials.js";
export {
  OwnerRepository, OwnerRepositoryError, createOwnerRepository,
  type NewOwnerRecord, type OwnerCredentialRecord, type OwnerMetadata, type OwnerRepositoryErrorCode,
} from "./owner-repository.js";
export {
  OwnerBootstrapError, createOwnerBootstrapService,
  type OwnerAuthenticationInput, type OwnerBootstrapErrorCode, type OwnerBootstrapInput, type OwnerBootstrapService,
} from "./owner-service.js";
export { SessionManager, type SessionManagerOptions } from "./session-manager.js";
export { SessionRepository } from "./session-repository.js";
export {
  SESSION_ABSOLUTE_TTL_MS, SESSION_COOKIE_NAME, SESSION_IDLE_TTL_MS, SESSION_TOKEN_BYTES, SessionError,
  type CreatedSession, type SessionErrorCode, type SessionMetadata, type SessionPolicy, type StoredSession,
} from "./session-types.js";
export { clearSessionCookie, parseSessionCookieHeader, serializeSessionCookie } from "./cookie-parser.js";
export { createAllowedOrigins, originAllowed, type OriginPolicyOptions } from "./origin.js";
export { guardManagementRequest, type GuardResult } from "./guard.js";
export { PairingManager, pairingProof, pairingTranscript, type PairingManagementAuthorizer, type PairingManagerOptions } from "./pairing-manager.js";
export { PairingRepository } from "./pairing-repository.js";
export { PAIRING_CODE_ALPHABET, PAIRING_CODE_LENGTH, PAIRING_MAX_ATTEMPTS, PAIRING_MAX_TTL_MS, PairingError, type EnrollmentAuthorization, type PairingErrorCode, type PairingPresentation, type PairingProofInput } from "./pairing-types.js";
export { InferenceTokenManager, createInferenceTokenManager, type InferenceTokenManagerOptions, type ManagementAuthorizer } from "./inference-manager.js";
export { generateInferenceToken, inferenceTokenDigest, parseAuthorizationBearer, validInferenceToken } from "./inference-bearer.js";
export {
  INFERENCE_DEFAULT_TTL_MS, INFERENCE_MAX_TTL_MS, INFERENCE_MIN_TTL_MS, INFERENCE_SCOPES, INFERENCE_TOKEN_BYTES, InferenceTokenError,
  type InferenceAuthorizationResult, type InferenceScope, type InferenceTokenErrorCode, type InferenceTokenMetadata, type IssuedInferenceToken, type StoredInferenceToken,
} from "./inference-types.js";
