// ============================================================================
// MCP Sentinel — Core Types & Asset Graph Model
// 18 entity types for the unified MCP security asset graph
// ============================================================================

import { v4 as uuidv4 } from 'uuid';

// ---------------------------------------------------------------------------
// Enums & Constants
// ---------------------------------------------------------------------------

export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export enum TransportType {
  STDIO = 'stdio',
  HTTP = 'http',
  SSE = 'sse',
  STREAMABLE_HTTP = 'streamable-http',
  UNKNOWN = 'unknown',
}

export enum AuthPosture {
  OAUTH = 'oauth',
  API_KEY = 'api-key',
  BEARER_TOKEN = 'bearer-token',
  NONE = 'none',
  UNKNOWN = 'unknown',
}

export enum ApprovalStatus {
  APPROVED = 'approved',
  DENIED = 'denied',
  PENDING = 'pending',
  WAIVED = 'waived',
  EXPIRED = 'expired',
}

export enum DecisionVerdict {
  ALLOW = 'allow',
  DENY = 'deny',
  REVIEW = 'review',
}

export enum FindingStatus {
  OPEN = 'open',
  RESOLVED = 'resolved',
  WAIVED = 'waived',
  FALSE_POSITIVE = 'false-positive',
}

export enum DetectorFamily {
  SECRET_SCANNER = 'secret-scanner',
  STARTUP_COMMAND = 'startup-command',
  AUTH_POSTURE = 'auth-posture',
  CAPABILITY_SURFACE = 'capability-surface',
  COMMAND_INJECTION = 'command-injection',
  PATH_TRAVERSAL = 'path-traversal',
  SSRF = 'ssrf',
  TOKEN_PASSTHROUGH = 'token-passthrough',
  TOOL_POISONING = 'tool-poisoning',
  DEPENDENCY_RISK = 'dependency-risk',
  VERSION_DRIFT = 'version-drift',
  NETWORK_EXFILTRATION = 'network-exfiltration',
}

export enum ClientType {
  CLAUDE_DESKTOP = 'claude-desktop',
  CURSOR = 'cursor',
  VSCODE = 'vscode',
  CLAUDE_CODE = 'claude-code',
  CUSTOM = 'custom',
}

export enum DetonationStatus {
  QUEUED = 'queued',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  TIMEOUT = 'timeout',
}

// ---------------------------------------------------------------------------
// Core Entity Interfaces — 18 types for the unified asset graph
// ---------------------------------------------------------------------------

export interface Host {
  id: string;
  hostname: string;
  os: string;
  discoveredAt: string;
  lastSeenAt: string;
  metadata: Record<string, unknown>;
}

export interface Client {
  id: string;
  hostId: string;
  type: ClientType;
  name: string;
  version: string;
  configPath: string;
  discoveredAt: string;
  lastSeenAt: string;
}

export interface Server {
  id: string;
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  transport: TransportType;
  url?: string;
  clientId: string;
  discoveredAt: string;
  lastScannedAt?: string;
  approvalStatus: ApprovalStatus;
  riskScore?: number;
  metadata: Record<string, unknown>;
}

export interface ServerVersion {
  id: string;
  serverId: string;
  version: string;
  packageVersion?: string;
  toolCount: number;
  promptCount: number;
  resourceCount: number;
  discoveredAt: string;
  diffFromPrevious?: VersionDiff;
}

export interface VersionDiff {
  addedTools: string[];
  removedTools: string[];
  changedDescriptions: Array<{ tool: string; before: string; after: string }>;
  changedScopes: Array<{ tool: string; before: string[]; after: string[] }>;
  changedEnvVars: Array<{ name: string; action: 'added' | 'removed' | 'changed' }>;
  changedScripts: Array<{ script: string; action: 'added' | 'removed' | 'changed' }>;
}

export interface Tool {
  id: string;
  serverId: string;
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  capabilities: string[];
  isDestructive: boolean;
  isWriteCapable: boolean;
  metadata: Record<string, unknown>;
}

export interface Prompt {
  id: string;
  serverId: string;
  name: string;
  description: string;
  arguments: Array<{ name: string; description: string; required: boolean }>;
}

export interface Resource {
  id: string;
  serverId: string;
  uri: string;
  name: string;
  description: string;
  mimeType?: string;
}

export interface Package {
  id: string;
  serverId: string;
  name: string;
  version: string;
  registry: string;
  homepage?: string;
  repository?: string;
  license?: string;
  hasPostinstallScript: boolean;
  isSigned: boolean;
  slsaLevel?: number;
  dependencies: PackageDependency[];
}

export interface PackageDependency {
  name: string;
  version: string;
  isDirect: boolean;
  hasKnownVulnerability: boolean;
  advisories: string[];
}

export interface Image {
  id: string;
  serverId: string;
  registry: string;
  repository: string;
  tag: string;
  digest: string;
  size: number;
  createdAt: string;
}

export interface Credential {
  id: string;
  serverId: string;
  type: AuthPosture;
  source: 'config' | 'env' | 'file' | 'runtime';
  name: string;
  isStatic: boolean;
  isLongLived: boolean;
  isExposed: boolean;
  detectedAt: string;
  location: string;
  redactedValue?: string;
}

export interface Identity {
  id: string;
  name: string;
  email?: string;
  role: string;
  permissions: string[];
  lastActiveAt: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  bundle: string;
  rules: PolicyRule[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
  createdBy: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  condition: PolicyCondition;
  action: DecisionVerdict;
  severity: Severity;
  isEnabled: boolean;
}

export interface PolicyCondition {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'greater_than' | 'less_than' | 'exists' | 'not_exists' | 'matches' | 'in' | 'not_in';
  value: unknown;
  and?: PolicyCondition[];
  or?: PolicyCondition[];
}

export interface Finding {
  id: string;
  serverId: string;
  serverVersionId?: string;
  detector: DetectorFamily;
  title: string;
  description: string;
  severity: Severity;
  confidence: number; // 0.0 to 1.0
  status: FindingStatus;
  evidence: FindingEvidence;
  remediation: string;
  references: string[];
  detectedAt: string;
  resolvedAt?: string;
  metadata: Record<string, unknown>;
}

export interface FindingEvidence {
  type: 'static' | 'runtime' | 'hybrid';
  location?: string;
  lineNumber?: number;
  snippet?: string;
  traceId?: string;
  artifacts: string[];
}

export interface EvidenceBundle {
  id: string;
  serverId: string;
  serverVersionId?: string;
  detonationId?: string;
  type: 'scan' | 'detonation' | 'audit';
  findings: string[]; // Finding IDs
  artifacts: EvidenceArtifact[];
  attestation?: SignedAttestation;
  createdAt: string;
  expiresAt?: string;
  metadata: Record<string, unknown>;
}

export interface EvidenceArtifact {
  name: string;
  type: 'json' | 'pcap' | 'dns' | 'screenshot' | 'trace' | 'sbom' | 'sarif' | 'log';
  path: string;
  size: number;
  hash: string;
}

export interface SignedAttestation {
  algorithm: string;
  signature: string;
  publicKey: string;
  timestamp: string;
  payload: string;
}

export interface RegistryEntry {
  id: string;
  serverId: string;
  registry: string;
  namespace: string;
  name: string;
  version: string;
  approvalStatus: ApprovalStatus;
  postureScore?: number;
  lastCheckedAt: string;
  metadata: Record<string, unknown>;
}

export interface Approval {
  id: string;
  serverId: string;
  serverVersionId?: string;
  status: ApprovalStatus;
  approvedBy?: string;
  reason: string;
  conditions: string[];
  createdAt: string;
  expiresAt?: string;
  metadata: Record<string, unknown>;
}

export interface Waiver {
  id: string;
  findingId: string;
  serverId: string;
  policyRuleId: string;
  owner: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  approvedBy: string;
  metadata: Record<string, unknown>;
}

export interface Trace {
  id: string;
  detonationId: string;
  serverId: string;
  status: DetonationStatus;
  startedAt: string;
  completedAt?: string;
  duration?: number;
  processTree: ProcessNode[];
  fileAccess: FileAccessEvent[];
  networkEvents: NetworkEvent[];
  envAccess: EnvAccessEvent[];
  honeytokenHits: HoneytokenHit[];
  probeResults: ProbeResult[];
  evidenceBundleId?: string;
}

export interface ProcessNode {
  pid: number;
  command: string;
  args: string[];
  parentPid?: number;
  startedAt: string;
  exitCode?: number;
}

export interface FileAccessEvent {
  path: string;
  operation: 'read' | 'write' | 'delete' | 'create' | 'rename';
  timestamp: string;
  success: boolean;
  size?: number;
}

export interface NetworkEvent {
  direction: 'outbound' | 'inbound';
  protocol: string;
  host: string;
  port: number;
  url?: string;
  method?: string;
  statusCode?: number;
  payloadSize?: number;
  timestamp: string;
  blocked: boolean;
}

export interface EnvAccessEvent {
  variable: string;
  operation: 'read' | 'write';
  value?: string;
  timestamp: string;
  isSensitive: boolean;
}

export interface HoneytokenHit {
  tokenId: string;
  tokenType: 'api-key' | 'file' | 'url' | 'metadata';
  accessedAt: string;
  accessMethod: string;
  destination?: string;
}

export interface ProbeResult {
  probeType: 'fuzz' | 'traversal' | 'injection' | 'oauth-discovery' | 'schema-drift';
  input: string;
  output?: string;
  wasBlocked: boolean;
  wasVulnerable: boolean;
  details: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Scan Configuration & Results
// ---------------------------------------------------------------------------

export interface ScanConfig {
  targets: ScanTarget[];
  detectors: DetectorFamily[];
  policyBundle: string;
  outputFormat: 'json' | 'sarif' | 'text';
  verbose: boolean;
  dryRun: boolean;
}

export interface ScanTarget {
  type: 'config-file' | 'directory' | 'registry' | 'server-url';
  path: string;
  clientType?: ClientType;
}

export interface ScanResult {
  id: string;
  startedAt: string;
  completedAt: string;
  duration: number;
  targets: ScanTarget[];
  serversDiscovered: number;
  serversScanned: number;
  findings: Finding[];
  riskScore: number;
  summary: ScanSummary;
  evidenceBundleId?: string;
}

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byDetector: Record<string, number>;
  byStatus: Record<FindingStatus, number>;
  topRisks: Finding[];
  passRate: number;
}

// ---------------------------------------------------------------------------
// Detonation Request & Result
// ---------------------------------------------------------------------------

export interface DetonationRequest {
  serverId: string;
  serverConfig: Partial<Server>;
  options: DetonationOptions;
}

export interface DetonationOptions {
  timeout: number; // ms
  enableHoneytokens: boolean;
  enableNetworkCapture: boolean;
  enableFileTracing: boolean;
  enableEnvTracing: boolean;
  enableFuzzing: boolean;
  syntheticWorkspace: boolean;
  allowedDomains: string[];
  probeTypes: string[];
}

export interface DetonationResult {
  id: string;
  serverId: string;
  status: DetonationStatus;
  startedAt: string;
  completedAt?: string;
  duration?: number;
  trace: Trace;
  findings: Finding[];
  evidenceBundle: EvidenceBundle;
}

// ---------------------------------------------------------------------------
// Policy Decision
// ---------------------------------------------------------------------------

export interface PolicyDecision {
  id: string;
  serverId: string;
  policyId: string;
  ruleId: string;
  verdict: DecisionVerdict;
  reason: string;
  findings: string[];
  waiverId?: string;
  evaluatedAt: string;
  metadata: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Helper to create IDs
// ---------------------------------------------------------------------------

export function createId(): string {
  return uuidv4();
}

export function createTimestamp(): string {
  return new Date().toISOString();
}
