// ============================================================================
// Output Formatters — JSON, SARIF, Human-Readable Text
// ============================================================================

import {
  ScanResult, ScanSummary, Finding, Severity, FindingStatus,
} from './types';

// ---------------------------------------------------------------------------
// JSON Formatter
// ---------------------------------------------------------------------------

export function formatJSON(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

// ---------------------------------------------------------------------------
// SARIF v2.1.0 Formatter — for GitHub Code Scanning and VS Code
// ---------------------------------------------------------------------------

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string };
    region?: { startLine: number; startColumn?: number };
  };
}

interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc: string;
  endTimeUtc: string;
}

const SEVERITY_TO_SARIF_LEVEL: Record<Severity, string> = {
  [Severity.CRITICAL]: 'error',
  [Severity.HIGH]: 'error',
  [Severity.MEDIUM]: 'warning',
  [Severity.LOW]: 'note',
  [Severity.INFO]: 'note',
};

export function formatSARIF(result: ScanResult): string {
  const rules: SarifRule[] = [];
  const ruleIndex: Map<string, number> = new Map();

  // Build unique rules from findings
  for (const finding of result.findings) {
    const ruleId = `sentinel/${finding.detector}/${finding.title.toLowerCase().replace(/\s+/g, '-')}`;
    if (!ruleIndex.has(ruleId)) {
      ruleIndex.set(ruleId, rules.length);
      rules.push({
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        defaultConfiguration: { level: SEVERITY_TO_SARIF_LEVEL[finding.severity] },
      });
    }
  }

  const results: SarifResult[] = result.findings.map(finding => {
    const ruleId = `sentinel/${finding.detector}/${finding.title.toLowerCase().replace(/\s+/g, '-')}`;
    return {
      ruleId,
      level: SEVERITY_TO_SARIF_LEVEL[finding.severity],
      message: { text: `${finding.description}\n\nRemediation: ${finding.remediation}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: finding.evidence.location || 'unknown' },
          region: finding.evidence.lineNumber ? { startLine: finding.evidence.lineNumber } : undefined,
        },
      }],
      fingerprints: { 'sentinel/finding-id': finding.id },
    };
  });

  const sarif: SarifReport = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'MCP Sentinel',
          version: '1.0.0',
          informationUri: 'https://github.com/mcp-sentinel',
          rules,
        },
      },
      results,
      invocations: [{
        executionSuccessful: true,
        startTimeUtc: result.startedAt,
        endTimeUtc: result.completedAt,
      }],
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

// ---------------------------------------------------------------------------
// Human-Readable Text Formatter
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<Severity, string> = {
  [Severity.CRITICAL]: '\x1b[91m', // bright red
  [Severity.HIGH]: '\x1b[31m',     // red
  [Severity.MEDIUM]: '\x1b[33m',   // yellow
  [Severity.LOW]: '\x1b[36m',      // cyan
  [Severity.INFO]: '\x1b[37m',     // white
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';

export function formatText(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}╔══════════════════════════════════════════════════════════════╗${RESET}`);
  lines.push(`${BOLD}║              MCP SENTINEL — SECURITY POSTURE REPORT          ║${RESET}`);
  lines.push(`${BOLD}╚══════════════════════════════════════════════════════════════╝${RESET}`);
  lines.push('');

  // Summary
  lines.push(`${BOLD}Scan Summary${RESET}`);
  lines.push(`  Completed:     ${result.completedAt}`);
  lines.push(`  Duration:      ${result.duration}ms`);
  lines.push(`  Servers found: ${result.serversDiscovered}`);
  lines.push(`  Servers scanned: ${result.serversScanned}`);
  lines.push(`  Overall Risk:  ${riskBar(result.riskScore)}`);
  lines.push('');

  // Findings by severity
  lines.push(`${BOLD}Findings by Severity${RESET}`);
  for (const sev of [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]) {
    const count = result.summary.bySeverity[sev] || 0;
    const color = SEVERITY_COLORS[sev];
    const bar = '█'.repeat(Math.min(count, 40));
    lines.push(`  ${color}${sev.toUpperCase().padEnd(10)}${RESET} ${bar} ${count}`);
  }
  lines.push('');

  // Findings by detector
  lines.push(`${BOLD}Findings by Detector${RESET}`);
  for (const [detector, count] of Object.entries(result.summary.byDetector)) {
    lines.push(`  ${detector.padEnd(25)} ${count}`);
  }
  lines.push('');

  // Top risks
  if (result.summary.topRisks.length > 0) {
    lines.push(`${BOLD}Top Risks${RESET}`);
    for (const finding of result.summary.topRisks.slice(0, 10)) {
      const color = SEVERITY_COLORS[finding.severity];
      lines.push(`  ${color}[${finding.severity.toUpperCase()}]${RESET} ${finding.title}`);
      lines.push(`    ${DIM}${finding.description}${RESET}`);
      if (finding.evidence.location) {
        lines.push(`    ${DIM}Location: ${finding.evidence.location}${RESET}`);
      }
      lines.push(`    ${DIM}Remediation: ${finding.remediation}${RESET}`);
      lines.push('');
    }
  }

  // Detailed findings
  lines.push(`${BOLD}${'─'.repeat(60)}${RESET}`);
  lines.push(`${BOLD}All Findings (${result.findings.length})${RESET}`);
  lines.push(`${BOLD}${'─'.repeat(60)}${RESET}`);

  for (let i = 0; i < result.findings.length; i++) {
    const f = result.findings[i];
    const color = SEVERITY_COLORS[f.severity];
    lines.push(`  ${DIM}#${i + 1}${RESET} ${color}[${f.severity.toUpperCase()}]${RESET} ${BOLD}${f.title}${RESET}`);
    lines.push(`     Detector:    ${f.detector}`);
    lines.push(`     Server:      ${f.serverId}`);
    lines.push(`     Description: ${f.description}`);
    if (f.evidence.location) {
      lines.push(`     Location:    ${f.evidence.location}${f.evidence.lineNumber ? `:${f.evidence.lineNumber}` : ''}`);
    }
    if (f.evidence.snippet) {
      lines.push(`     Snippet:     ${f.evidence.snippet}`);
    }
    lines.push(`     Remediation: ${f.remediation}`);
    lines.push(`     Confidence:  ${(f.confidence * 100).toFixed(0)}%`);
    lines.push(`     Status:      ${f.status}`);
    lines.push('');
  }

  // Pass rate
  lines.push(`${BOLD}Pass Rate: ${(result.summary.passRate * 100).toFixed(1)}%${RESET}`);
  lines.push('');

  return lines.join('\n');
}

function riskBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  let color: string;
  if (score >= 9) color = '\x1b[91m';
  else if (score >= 7) color = '\x1b[31m';
  else if (score >= 4) color = '\x1b[33m';
  else if (score >= 2) color = '\x1b[36m';
  else color = '\x1b[32m';

  return `${color}${'█'.repeat(filled)}${'░'.repeat(empty)}${RESET} ${score.toFixed(1)}/10`;
}

// ---------------------------------------------------------------------------
// Summary Builder
// ---------------------------------------------------------------------------

export function buildScanSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  const byDetector: Record<string, number> = {};
  const byStatus: Record<FindingStatus, number> = {
    [FindingStatus.OPEN]: 0,
    [FindingStatus.RESOLVED]: 0,
    [FindingStatus.WAIVED]: 0,
    [FindingStatus.FALSE_POSITIVE]: 0,
  };

  for (const f of findings) {
    bySeverity[f.severity]++;
    byDetector[f.detector] = (byDetector[f.detector] || 0) + 1;
    byStatus[f.status]++;
  }

  const openFindings = findings.filter(f => f.status === FindingStatus.OPEN);
  const topRisks = openFindings
    .sort((a, b) => {
      const sevOrder = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];
      return sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity);
    })
    .slice(0, 10);

  const passRate = findings.length === 0
    ? 1.0
    : (findings.length - openFindings.length) / findings.length;

  return {
    totalFindings: findings.length,
    bySeverity,
    byDetector,
    byStatus,
    topRisks,
    passRate,
  };
}
