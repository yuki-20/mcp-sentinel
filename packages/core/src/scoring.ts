// ============================================================================
// Risk Scoring Engine
// Formula: Risk = impact × exploitability × exposure × confidence
// Adjusted downward only for verified compensating controls
// ============================================================================

import { Finding, Severity, Server, TransportType, AuthPosture } from './types';

export interface RiskFactors {
  impact: number;        // 1-10: how bad if exploited
  exploitability: number; // 1-10: how easy to exploit
  exposure: number;       // 1-10: how exposed/reachable
  confidence: number;     // 0.0-1.0: detector confidence
}

export interface CompensatingControl {
  name: string;
  verified: boolean;
  reductionFactor: number; // 0.0-1.0 reduction multiplier
}

export interface RiskScore {
  raw: number;             // Before compensating controls
  adjusted: number;        // After compensating controls
  grade: RiskGrade;
  factors: RiskFactors;
  compensatingControls: CompensatingControl[];
}

export enum RiskGrade {
  CRITICAL = 'A', // 9.0-10.0
  HIGH = 'B',     // 7.0-8.9
  MEDIUM = 'C',   // 4.0-6.9
  LOW = 'D',      // 2.0-3.9
  MINIMAL = 'E',  // 0.0-1.9
}

// ---------------------------------------------------------------------------
// Severity → Impact mapping
// ---------------------------------------------------------------------------

const SEVERITY_IMPACT: Record<Severity, number> = {
  [Severity.CRITICAL]: 10,
  [Severity.HIGH]: 8,
  [Severity.MEDIUM]: 5,
  [Severity.LOW]: 3,
  [Severity.INFO]: 1,
};

// ---------------------------------------------------------------------------
// Transport → Exposure mapping
// ---------------------------------------------------------------------------

const TRANSPORT_EXPOSURE: Record<TransportType, number> = {
  [TransportType.HTTP]: 9,
  [TransportType.SSE]: 8,
  [TransportType.STREAMABLE_HTTP]: 8,
  [TransportType.STDIO]: 4,
  [TransportType.UNKNOWN]: 6,
};

// ---------------------------------------------------------------------------
// Auth posture → Exploitability modifier
// ---------------------------------------------------------------------------

const AUTH_EXPLOITABILITY_MOD: Record<AuthPosture, number> = {
  [AuthPosture.NONE]: 1.0,
  [AuthPosture.UNKNOWN]: 0.8,
  [AuthPosture.API_KEY]: 0.6,
  [AuthPosture.BEARER_TOKEN]: 0.5,
  [AuthPosture.OAUTH]: 0.3,
};

// ---------------------------------------------------------------------------
// Core scoring functions
// ---------------------------------------------------------------------------

export function calculateRiskScore(
  factors: RiskFactors,
  compensatingControls: CompensatingControl[] = []
): RiskScore {
  // Raw score: geometric mean of impact, exploitability, exposure, scaled by confidence
  const rawProduct = factors.impact * factors.exploitability * factors.exposure;
  const normalizedRaw = Math.pow(rawProduct, 1 / 3); // Cube root for geometric mean
  const raw = Math.min(10, normalizedRaw * factors.confidence);

  // Apply compensating controls — only verified ones reduce the score
  let adjusted = raw;
  for (const control of compensatingControls) {
    if (control.verified) {
      adjusted *= (1 - control.reductionFactor);
    }
  }
  adjusted = Math.max(0, Math.min(10, adjusted));

  return {
    raw: Math.round(raw * 100) / 100,
    adjusted: Math.round(adjusted * 100) / 100,
    grade: scoreToGrade(adjusted),
    factors,
    compensatingControls,
  };
}

export function scoreToGrade(score: number): RiskGrade {
  if (score >= 9.0) return RiskGrade.CRITICAL;
  if (score >= 7.0) return RiskGrade.HIGH;
  if (score >= 4.0) return RiskGrade.MEDIUM;
  if (score >= 2.0) return RiskGrade.LOW;
  return RiskGrade.MINIMAL;
}

export function scoreFinding(finding: Finding, server?: Server): RiskScore {
  const impact = SEVERITY_IMPACT[finding.severity];

  // Exploitability depends on how easy the vulnerability is to trigger
  let exploitability = findingExploitability(finding);
  if (server) {
    const authMod = AUTH_EXPLOITABILITY_MOD[
      (server.metadata?.authPosture as AuthPosture) || AuthPosture.UNKNOWN
    ];
    exploitability = Math.min(10, exploitability * (1 + (1 - authMod)));
  }

  // Exposure depends on transport and whether server is local/remote
  let exposure = 5; // default
  if (server) {
    exposure = TRANSPORT_EXPOSURE[server.transport];
  }

  const factors: RiskFactors = {
    impact,
    exploitability: Math.min(10, exploitability),
    exposure: Math.min(10, exposure),
    confidence: finding.confidence,
  };

  return calculateRiskScore(factors);
}

function findingExploitability(finding: Finding): number {
  // Higher exploitability for runtime-confirmed vs static-only findings
  const baseExploitability: Record<string, number> = {
    'secret-scanner': 7,
    'startup-command': 9,
    'auth-posture': 6,
    'capability-surface': 4,
    'command-injection': 9,
    'path-traversal': 8,
    'ssrf': 7,
    'token-passthrough': 8,
    'tool-poisoning': 5,
    'dependency-risk': 6,
    'version-drift': 4,
    'network-exfiltration': 7,
  };

  const base = baseExploitability[finding.detector] || 5;

  // Runtime-confirmed findings are more exploitable
  if (finding.evidence.type === 'runtime') return Math.min(10, base + 2);
  if (finding.evidence.type === 'hybrid') return Math.min(10, base + 1);
  return base;
}

export function aggregateServerRisk(findings: Finding[], server: Server): RiskScore {
  if (findings.length === 0) {
    return calculateRiskScore({
      impact: 0,
      exploitability: 0,
      exposure: TRANSPORT_EXPOSURE[server.transport],
      confidence: 1.0,
    });
  }

  // Aggregate: use the highest individual score, boosted by finding count
  const scores = findings.map(f => scoreFinding(f, server));
  const maxScore = Math.max(...scores.map(s => s.adjusted));
  const countBoost = Math.min(2, Math.log2(findings.length + 1) * 0.5);

  const aggregated = Math.min(10, maxScore + countBoost);

  return {
    raw: aggregated,
    adjusted: aggregated,
    grade: scoreToGrade(aggregated),
    factors: {
      impact: Math.max(...scores.map(s => s.factors.impact)),
      exploitability: Math.max(...scores.map(s => s.factors.exploitability)),
      exposure: Math.max(...scores.map(s => s.factors.exposure)),
      confidence: Math.max(...scores.map(s => s.factors.confidence)),
    },
    compensatingControls: [],
  };
}
