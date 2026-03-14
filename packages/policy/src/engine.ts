// ============================================================================
// Policy Service — Decision Engine
// JSON-based rules (OPA/Cedar-inspired), waivers, bundles, decision logging
// ============================================================================

import {
  Server, Finding, Policy, PolicyCondition,
  PolicyDecision, DecisionVerdict, Severity, Waiver,
  createId, createTimestamp,
} from '@mcp-sentinel/core';

// ---------------------------------------------------------------------------
// Policy Evaluator
// ---------------------------------------------------------------------------

export class PolicyEngine {
  private policies: Policy[] = [];
  private waivers: Map<string, Waiver> = new Map();
  private decisions: PolicyDecision[] = [];
  private dryRun: boolean = false;

  constructor(dryRun: boolean = false) {
    this.dryRun = dryRun;
  }

  loadPolicies(policies: Policy[]): void {
    this.policies = policies.filter(p => p.isActive);
  }

  loadWaivers(waivers: Waiver[]): void {
    for (const w of waivers) {
      if (w.isActive && new Date(w.expiresAt) > new Date()) {
        this.waivers.set(`${w.serverId}:${w.policyRuleId}`, w);
      }
    }
  }

  evaluate(server: Server, findings: Finding[]): PolicyDecision[] {
    const decisions: PolicyDecision[] = [];

    for (const policy of this.policies) {
      for (const rule of policy.rules) {
        if (!rule.isEnabled) continue;

        const matchingFindings = findings.filter(f =>
          this.evaluateCondition(rule.condition, server, f)
        );

        if (matchingFindings.length > 0) {
          // Check for waiver
          const waiverKey = `${server.id}:${rule.id}`;
          const waiver = this.waivers.get(waiverKey);

          const decision: PolicyDecision = {
            id: createId(),
            serverId: server.id,
            policyId: policy.id,
            ruleId: rule.id,
            verdict: waiver ? DecisionVerdict.ALLOW : rule.action,
            reason: waiver
              ? `Waived by ${waiver.approvedBy}: ${waiver.reason} (expires ${waiver.expiresAt})`
              : `Rule "${rule.name}" triggered: ${rule.description}`,
            findings: matchingFindings.map(f => f.id),
            waiverId: waiver?.id,
            evaluatedAt: createTimestamp(),
            metadata: {
              dryRun: this.dryRun,
              matchCount: matchingFindings.length,
              policyBundle: policy.bundle,
            },
          };

          decisions.push(decision);
        }
      }
    }

    this.decisions.push(...decisions);
    return decisions;
  }

  private evaluateCondition(condition: PolicyCondition, server: Server, finding: Finding): boolean {
    const value = this.resolveField(condition.field, server, finding);

    let match = false;
    switch (condition.operator) {
      case 'equals':
        match = value === condition.value;
        break;
      case 'not_equals':
        match = value !== condition.value;
        break;
      case 'contains':
        match = typeof value === 'string' && value.includes(condition.value as string);
        break;
      case 'not_contains':
        match = typeof value === 'string' && !value.includes(condition.value as string);
        break;
      case 'greater_than':
        match = typeof value === 'number' && value > (condition.value as number);
        break;
      case 'less_than':
        match = typeof value === 'number' && value < (condition.value as number);
        break;
      case 'exists':
        match = value !== undefined && value !== null;
        break;
      case 'not_exists':
        match = value === undefined || value === null;
        break;
      case 'matches':
        match = typeof value === 'string' && new RegExp(condition.value as string).test(value);
        break;
      case 'in':
        match = Array.isArray(condition.value) && (condition.value as any[]).includes(value);
        break;
      case 'not_in':
        match = Array.isArray(condition.value) && !(condition.value as any[]).includes(value);
        break;
      default:
        match = false;
    }

    // Handle AND/OR compound conditions
    if (condition.and) {
      match = match && condition.and.every((c: PolicyCondition) => this.evaluateCondition(c, server, finding));
    }
    if (condition.or) {
      match = match || condition.or.some((c: PolicyCondition) => this.evaluateCondition(c, server, finding));
    }

    return match;
  }

  private resolveField(field: string, server: Server, finding: Finding): unknown {
    const parts = field.split('.');
    const root = parts[0];
    const rest = parts.slice(1);

    let obj: any;
    switch (root) {
      case 'server': obj = server; break;
      case 'finding': obj = finding; break;
      default: return undefined;
    }

    for (const part of rest) {
      if (obj === undefined || obj === null) return undefined;
      obj = obj[part];
    }

    return obj;
  }

  getDecisions(): PolicyDecision[] {
    return [...this.decisions];
  }

  getVerdictSummary(decisions: PolicyDecision[]): {
    allowed: number;
    denied: number;
    review: number;
    waived: number;
  } {
    return {
      allowed: decisions.filter(d => d.verdict === DecisionVerdict.ALLOW).length,
      denied: decisions.filter(d => d.verdict === DecisionVerdict.DENY).length,
      review: decisions.filter(d => d.verdict === DecisionVerdict.REVIEW).length,
      waived: decisions.filter(d => d.waiverId).length,
    };
  }
}

// ---------------------------------------------------------------------------
// Built-in Policy Bundles
// ---------------------------------------------------------------------------

export function getStrictPolicyBundle(): Policy {
  return {
    id: 'policy-strict',
    name: 'Strict Security',
    description: 'Strictest policy bundle — blocks most risks, requires full evidence and approval for write-capable tools',
    bundle: 'strict',
    rules: [
      {
        id: 'strict-001',
        name: 'Deny critical severity findings',
        description: 'Block any server with critical severity findings',
        condition: { field: 'finding.severity', operator: 'equals', value: 'critical' },
        action: DecisionVerdict.DENY,
        severity: Severity.CRITICAL,
        isEnabled: true,
      },
      {
        id: 'strict-002',
        name: 'Deny high severity findings',
        description: 'Block any server with high severity findings',
        condition: { field: 'finding.severity', operator: 'equals', value: 'high' },
        action: DecisionVerdict.DENY,
        severity: Severity.HIGH,
        isEnabled: true,
      },
      {
        id: 'strict-003',
        name: 'Deny remote servers without OAuth',
        description: 'Block remote servers that do not use OAuth authentication',
        condition: {
          field: 'server.transport',
          operator: 'not_equals',
          value: 'stdio',
          and: [{
            field: 'server.metadata.authPosture',
            operator: 'not_equals',
            value: 'oauth',
          }],
        },
        action: DecisionVerdict.DENY,
        severity: Severity.HIGH,
        isEnabled: true,
      },
      {
        id: 'strict-004',
        name: 'Deny servers with static credentials',
        description: 'Block servers that use hardcoded API keys or passwords',
        condition: { field: 'finding.detector', operator: 'equals', value: 'secret-scanner' },
        action: DecisionVerdict.DENY,
        severity: Severity.HIGH,
        isEnabled: true,
      },
      {
        id: 'strict-005',
        name: 'Deny risky startup commands',
        description: 'Block servers with dangerous startup commands (curl|sh, sudo, etc.)',
        condition: { field: 'finding.detector', operator: 'equals', value: 'startup-command' },
        action: DecisionVerdict.DENY,
        severity: Severity.CRITICAL,
        isEnabled: true,
      },
      {
        id: 'strict-006',
        name: 'Review dependency risks',
        description: 'Require review for servers with dependency vulnerabilities',
        condition: { field: 'finding.detector', operator: 'equals', value: 'dependency-risk' },
        action: DecisionVerdict.REVIEW,
        severity: Severity.MEDIUM,
        isEnabled: true,
      },
    ],
    isActive: true,
    createdAt: createTimestamp(),
    updatedAt: createTimestamp(),
    createdBy: 'system',
  };
}

export function getStandardPolicyBundle(): Policy {
  return {
    id: 'policy-standard',
    name: 'Standard Security',
    description: 'Balanced policy — blocks critical and high risks, reviews medium risks',
    bundle: 'standard',
    rules: [
      {
        id: 'standard-001',
        name: 'Deny critical severity findings',
        description: 'Block any server with critical severity findings',
        condition: { field: 'finding.severity', operator: 'equals', value: 'critical' },
        action: DecisionVerdict.DENY,
        severity: Severity.CRITICAL,
        isEnabled: true,
      },
      {
        id: 'standard-002',
        name: 'Review high severity findings',
        description: 'Require review for high severity findings',
        condition: { field: 'finding.severity', operator: 'equals', value: 'high' },
        action: DecisionVerdict.REVIEW,
        severity: Severity.HIGH,
        isEnabled: true,
      },
      {
        id: 'standard-003',
        name: 'Deny command injection',
        description: 'Block servers with command injection vulnerabilities',
        condition: { field: 'finding.detector', operator: 'equals', value: 'command-injection' },
        action: DecisionVerdict.DENY,
        severity: Severity.CRITICAL,
        isEnabled: true,
      },
      {
        id: 'standard-004',
        name: 'Deny token passthrough',
        description: 'Block servers that forward user tokens to downstream services',
        condition: { field: 'finding.detector', operator: 'equals', value: 'token-passthrough' },
        action: DecisionVerdict.DENY,
        severity: Severity.CRITICAL,
        isEnabled: true,
      },
    ],
    isActive: true,
    createdAt: createTimestamp(),
    updatedAt: createTimestamp(),
    createdBy: 'system',
  };
}

export function getPermissivePolicyBundle(): Policy {
  return {
    id: 'policy-permissive',
    name: 'Permissive Security',
    description: 'Lenient policy — only blocks critical risks, allows everything else with findings noted',
    bundle: 'permissive',
    rules: [
      {
        id: 'permissive-001',
        name: 'Deny critical severity findings',
        description: 'Block only critical severity findings',
        condition: { field: 'finding.severity', operator: 'equals', value: 'critical' },
        action: DecisionVerdict.DENY,
        severity: Severity.CRITICAL,
        isEnabled: true,
      },
    ],
    isActive: true,
    createdAt: createTimestamp(),
    updatedAt: createTimestamp(),
    createdBy: 'system',
  };
}

export function getAllPolicyBundles(): Policy[] {
  return [getStrictPolicyBundle(), getStandardPolicyBundle(), getPermissivePolicyBundle()];
}
