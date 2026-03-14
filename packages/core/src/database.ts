// ============================================================================
// Database Layer — SQLite for local mode, PostgreSQL-ready schema
// ============================================================================

import Database from 'better-sqlite3';
import path from 'path';
import {
  Server, Finding, EvidenceBundle, Policy, PolicyDecision,
  Waiver, Trace, ScanResult,
} from './types';

export class SentinelDB {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const resolvedPath = dbPath || path.join(process.cwd(), '.sentinel', 'sentinel.db');
    const dir = path.dirname(resolvedPath);
    // Ensure directory exists
    const fs = require('fs');
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    this.db = new Database(resolvedPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.initialize();
  }

  private initialize(): void {
    this.db.exec(`
      -- Hosts
      CREATE TABLE IF NOT EXISTS hosts (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        os TEXT,
        discovered_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      );

      -- Clients
      CREATE TABLE IF NOT EXISTS clients (
        id TEXT PRIMARY KEY,
        host_id TEXT REFERENCES hosts(id),
        type TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT,
        config_path TEXT NOT NULL,
        discovered_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      );

      -- Servers
      CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        command TEXT NOT NULL,
        args TEXT DEFAULT '[]',
        env TEXT DEFAULT '{}',
        transport TEXT NOT NULL DEFAULT 'unknown',
        url TEXT,
        client_id TEXT REFERENCES clients(id),
        discovered_at TEXT NOT NULL,
        last_scanned_at TEXT,
        approval_status TEXT DEFAULT 'pending',
        risk_score REAL,
        metadata TEXT DEFAULT '{}'
      );

      -- Server Versions
      CREATE TABLE IF NOT EXISTS server_versions (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        version TEXT NOT NULL,
        package_version TEXT,
        tool_count INTEGER DEFAULT 0,
        prompt_count INTEGER DEFAULT 0,
        resource_count INTEGER DEFAULT 0,
        discovered_at TEXT NOT NULL,
        diff_from_previous TEXT
      );

      -- Tools
      CREATE TABLE IF NOT EXISTS tools (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        name TEXT NOT NULL,
        description TEXT,
        input_schema TEXT DEFAULT '{}',
        capabilities TEXT DEFAULT '[]',
        is_destructive INTEGER DEFAULT 0,
        is_write_capable INTEGER DEFAULT 0,
        metadata TEXT DEFAULT '{}'
      );

      -- Prompts
      CREATE TABLE IF NOT EXISTS prompts (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        name TEXT NOT NULL,
        description TEXT,
        arguments TEXT DEFAULT '[]'
      );

      -- Resources
      CREATE TABLE IF NOT EXISTS resources (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        uri TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        mime_type TEXT
      );

      -- Packages
      CREATE TABLE IF NOT EXISTS packages (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        registry TEXT,
        homepage TEXT,
        repository TEXT,
        license TEXT,
        has_postinstall INTEGER DEFAULT 0,
        is_signed INTEGER DEFAULT 0,
        slsa_level INTEGER,
        dependencies TEXT DEFAULT '[]'
      );

      -- Credentials
      CREATE TABLE IF NOT EXISTS credentials (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        type TEXT NOT NULL,
        source TEXT NOT NULL,
        name TEXT NOT NULL,
        is_static INTEGER DEFAULT 0,
        is_long_lived INTEGER DEFAULT 0,
        is_exposed INTEGER DEFAULT 0,
        detected_at TEXT NOT NULL,
        location TEXT,
        redacted_value TEXT
      );

      -- Findings
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        server_version_id TEXT REFERENCES server_versions(id),
        detector TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence REAL DEFAULT 1.0,
        status TEXT DEFAULT 'open',
        evidence TEXT DEFAULT '{}',
        remediation TEXT,
        references_list TEXT DEFAULT '[]',
        detected_at TEXT NOT NULL,
        resolved_at TEXT,
        metadata TEXT DEFAULT '{}'
      );

      -- Evidence Bundles
      CREATE TABLE IF NOT EXISTS evidence_bundles (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        server_version_id TEXT REFERENCES server_versions(id),
        detonation_id TEXT,
        type TEXT NOT NULL DEFAULT 'scan',
        findings TEXT DEFAULT '[]',
        artifacts TEXT DEFAULT '[]',
        attestation TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        metadata TEXT DEFAULT '{}'
      );

      -- Policies
      CREATE TABLE IF NOT EXISTS policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT,
        bundle TEXT NOT NULL DEFAULT 'default',
        rules TEXT DEFAULT '[]',
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        created_by TEXT DEFAULT 'system'
      );

      -- Policy Decisions
      CREATE TABLE IF NOT EXISTS policy_decisions (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        policy_id TEXT NOT NULL REFERENCES policies(id),
        rule_id TEXT NOT NULL,
        verdict TEXT NOT NULL,
        reason TEXT,
        findings TEXT DEFAULT '[]',
        waiver_id TEXT,
        evaluated_at TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      );

      -- Waivers
      CREATE TABLE IF NOT EXISTS waivers (
        id TEXT PRIMARY KEY,
        finding_id TEXT NOT NULL REFERENCES findings(id),
        server_id TEXT NOT NULL REFERENCES servers(id),
        policy_rule_id TEXT NOT NULL,
        owner TEXT NOT NULL,
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        approved_by TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      );

      -- Approvals
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        server_id TEXT NOT NULL REFERENCES servers(id),
        server_version_id TEXT REFERENCES server_versions(id),
        status TEXT NOT NULL DEFAULT 'pending',
        approved_by TEXT,
        reason TEXT,
        conditions TEXT DEFAULT '[]',
        created_at TEXT NOT NULL,
        expires_at TEXT,
        metadata TEXT DEFAULT '{}'
      );

      -- Traces (Detonation)
      CREATE TABLE IF NOT EXISTS traces (
        id TEXT PRIMARY KEY,
        detonation_id TEXT NOT NULL,
        server_id TEXT NOT NULL REFERENCES servers(id),
        status TEXT NOT NULL DEFAULT 'queued',
        started_at TEXT NOT NULL,
        completed_at TEXT,
        duration INTEGER,
        process_tree TEXT DEFAULT '[]',
        file_access TEXT DEFAULT '[]',
        network_events TEXT DEFAULT '[]',
        env_access TEXT DEFAULT '[]',
        honeytoken_hits TEXT DEFAULT '[]',
        probe_results TEXT DEFAULT '[]',
        evidence_bundle_id TEXT REFERENCES evidence_bundles(id)
      );

      -- Scan Results
      CREATE TABLE IF NOT EXISTS scan_results (
        id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL,
        duration INTEGER NOT NULL,
        targets TEXT DEFAULT '[]',
        servers_discovered INTEGER DEFAULT 0,
        servers_scanned INTEGER DEFAULT 0,
        risk_score REAL DEFAULT 0,
        summary TEXT DEFAULT '{}',
        evidence_bundle_id TEXT REFERENCES evidence_bundles(id)
      );

      -- Audit Log (Immutable)
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        actor TEXT DEFAULT 'system',
        details TEXT DEFAULT '{}',
        timestamp TEXT NOT NULL
      );

      -- Registry Entries
      CREATE TABLE IF NOT EXISTS registry_entries (
        id TEXT PRIMARY KEY,
        server_id TEXT REFERENCES servers(id),
        registry TEXT NOT NULL,
        namespace TEXT,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        approval_status TEXT DEFAULT 'pending',
        posture_score REAL,
        last_checked_at TEXT NOT NULL,
        metadata TEXT DEFAULT '{}'
      );

      -- Indexes for performance
      CREATE INDEX IF NOT EXISTS idx_findings_server ON findings(server_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector);
      CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
      CREATE INDEX IF NOT EXISTS idx_servers_approval ON servers(approval_status);
      CREATE INDEX IF NOT EXISTS idx_traces_detonation ON traces(detonation_id);
      CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id);
      CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
      CREATE INDEX IF NOT EXISTS idx_waivers_active ON waivers(is_active);
      CREATE INDEX IF NOT EXISTS idx_policy_decisions_server ON policy_decisions(server_id);
    `);
  }

  // ---------------------------------------------------------------------------
  // Server CRUD
  // ---------------------------------------------------------------------------

  upsertServer(server: Server): void {
    // Auto-create client record if clientId is provided but doesn't exist
    if (server.clientId) {
      const existingClient = this.db.prepare('SELECT id FROM clients WHERE id = ?').get(server.clientId);
      if (!existingClient) {
        this.db.prepare(`
          INSERT OR IGNORE INTO clients (id, host_id, type, name, version, config_path, discovered_at, last_seen_at)
          VALUES (@id, NULL, 'auto-discovered', @name, NULL, 'unknown', @discoveredAt, @discoveredAt)
        `).run({
          id: server.clientId,
          name: server.clientId,
          discoveredAt: server.discoveredAt,
        });
      }
    }

    const stmt = this.db.prepare(`
      INSERT INTO servers (id, name, command, args, env, transport, url, client_id, discovered_at, last_scanned_at, approval_status, risk_score, metadata)
      VALUES (@id, @name, @command, @args, @env, @transport, @url, @clientId, @discoveredAt, @lastScannedAt, @approvalStatus, @riskScore, @metadata)
      ON CONFLICT(id) DO UPDATE SET
        name = @name, command = @command, args = @args, env = @env,
        transport = @transport, url = @url, last_scanned_at = @lastScannedAt,
        approval_status = @approvalStatus, risk_score = @riskScore, metadata = @metadata
    `);
    stmt.run({
      ...server,
      args: JSON.stringify(server.args),
      env: JSON.stringify(server.env),
      clientId: server.clientId || null,
      discoveredAt: server.discoveredAt,
      lastScannedAt: server.lastScannedAt || null,
      approvalStatus: server.approvalStatus,
      riskScore: server.riskScore || null,
      metadata: JSON.stringify(server.metadata),
    });
  }

  getAllServers(): Server[] {
    const rows = this.db.prepare('SELECT * FROM servers').all() as any[];
    return rows.map(this.rowToServer);
  }

  getServer(id: string): Server | undefined {
    const row = this.db.prepare('SELECT * FROM servers WHERE id = ?').get(id) as any;
    return row ? this.rowToServer(row) : undefined;
  }

  private rowToServer(row: any): Server {
    return {
      id: row.id,
      name: row.name,
      command: row.command,
      args: JSON.parse(row.args || '[]'),
      env: JSON.parse(row.env || '{}'),
      transport: row.transport,
      url: row.url,
      clientId: row.client_id,
      discoveredAt: row.discovered_at,
      lastScannedAt: row.last_scanned_at,
      approvalStatus: row.approval_status,
      riskScore: row.risk_score,
      metadata: JSON.parse(row.metadata || '{}'),
    };
  }

  // ---------------------------------------------------------------------------
  // Finding CRUD
  // ---------------------------------------------------------------------------

  insertFinding(finding: Finding): void {
    const stmt = this.db.prepare(`
      INSERT INTO findings (id, server_id, server_version_id, detector, title, description, severity, confidence, status, evidence, remediation, references_list, detected_at, resolved_at, metadata)
      VALUES (@id, @serverId, @serverVersionId, @detector, @title, @description, @severity, @confidence, @status, @evidence, @remediation, @referencesList, @detectedAt, @resolvedAt, @metadata)
    `);
    stmt.run({
      id: finding.id,
      serverId: finding.serverId,
      serverVersionId: finding.serverVersionId || null,
      detector: finding.detector,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      confidence: finding.confidence,
      status: finding.status,
      evidence: JSON.stringify(finding.evidence),
      remediation: finding.remediation,
      referencesList: JSON.stringify(finding.references),
      detectedAt: finding.detectedAt,
      resolvedAt: finding.resolvedAt || null,
      metadata: JSON.stringify(finding.metadata),
    });
  }

  getFindingsForServer(serverId: string): Finding[] {
    const rows = this.db.prepare('SELECT * FROM findings WHERE server_id = ?').all(serverId) as any[];
    return rows.map(this.rowToFinding);
  }

  getAllFindings(): Finding[] {
    const rows = this.db.prepare('SELECT * FROM findings ORDER BY detected_at DESC').all() as any[];
    return rows.map(this.rowToFinding);
  }

  getFindingsByDetector(detector: string): Finding[] {
    const rows = this.db.prepare('SELECT * FROM findings WHERE detector = ?').all(detector) as any[];
    return rows.map(this.rowToFinding);
  }

  getFindingsBySeverity(severity: string): Finding[] {
    const rows = this.db.prepare('SELECT * FROM findings WHERE severity = ?').all(severity) as any[];
    return rows.map(this.rowToFinding);
  }

  private rowToFinding(row: any): Finding {
    return {
      id: row.id,
      serverId: row.server_id,
      serverVersionId: row.server_version_id,
      detector: row.detector,
      title: row.title,
      description: row.description,
      severity: row.severity,
      confidence: row.confidence,
      status: row.status,
      evidence: JSON.parse(row.evidence || '{}'),
      remediation: row.remediation,
      references: JSON.parse(row.references_list || '[]'),
      detectedAt: row.detected_at,
      resolvedAt: row.resolved_at,
      metadata: JSON.parse(row.metadata || '{}'),
    };
  }

  // ---------------------------------------------------------------------------
  // Policy CRUD
  // ---------------------------------------------------------------------------

  upsertPolicy(policy: Policy): void {
    const stmt = this.db.prepare(`
      INSERT INTO policies (id, name, description, bundle, rules, is_active, created_at, updated_at, created_by)
      VALUES (@id, @name, @description, @bundle, @rules, @isActive, @createdAt, @updatedAt, @createdBy)
      ON CONFLICT(id) DO UPDATE SET
        name = @name, description = @description, bundle = @bundle, rules = @rules,
        is_active = @isActive, updated_at = @updatedAt
    `);
    stmt.run({
      id: policy.id,
      name: policy.name,
      description: policy.description,
      bundle: policy.bundle,
      rules: JSON.stringify(policy.rules),
      isActive: policy.isActive ? 1 : 0,
      createdAt: policy.createdAt,
      updatedAt: policy.updatedAt,
      createdBy: policy.createdBy,
    });
  }

  getActivePolicies(): Policy[] {
    const rows = this.db.prepare('SELECT * FROM policies WHERE is_active = 1').all() as any[];
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      description: row.description,
      bundle: row.bundle,
      rules: JSON.parse(row.rules || '[]'),
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      createdBy: row.created_by,
    }));
  }

  // ---------------------------------------------------------------------------
  // Waiver CRUD
  // ---------------------------------------------------------------------------

  insertWaiver(waiver: Waiver): void {
    const stmt = this.db.prepare(`
      INSERT INTO waivers (id, finding_id, server_id, policy_rule_id, owner, reason, created_at, expires_at, is_active, approved_by, metadata)
      VALUES (@id, @findingId, @serverId, @policyRuleId, @owner, @reason, @createdAt, @expiresAt, @isActive, @approvedBy, @metadata)
    `);
    stmt.run({
      id: waiver.id,
      findingId: waiver.findingId,
      serverId: waiver.serverId,
      policyRuleId: waiver.policyRuleId,
      owner: waiver.owner,
      reason: waiver.reason,
      createdAt: waiver.createdAt,
      expiresAt: waiver.expiresAt,
      isActive: waiver.isActive ? 1 : 0,
      approvedBy: waiver.approvedBy,
      metadata: JSON.stringify(waiver.metadata),
    });
  }

  getActiveWaivers(): Waiver[] {
    const rows = this.db.prepare(
      'SELECT * FROM waivers WHERE is_active = 1 AND expires_at > datetime(\'now\')'
    ).all() as any[];
    return rows.map(row => ({
      id: row.id,
      findingId: row.finding_id,
      serverId: row.server_id,
      policyRuleId: row.policy_rule_id,
      owner: row.owner,
      reason: row.reason,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      isActive: row.is_active === 1,
      approvedBy: row.approved_by,
      metadata: JSON.parse(row.metadata || '{}'),
    }));
  }

  // ---------------------------------------------------------------------------
  // Policy Decision
  // ---------------------------------------------------------------------------

  insertDecision(decision: PolicyDecision): void {
    const stmt = this.db.prepare(`
      INSERT INTO policy_decisions (id, server_id, policy_id, rule_id, verdict, reason, findings, waiver_id, evaluated_at, metadata)
      VALUES (@id, @serverId, @policyId, @ruleId, @verdict, @reason, @findings, @waiverId, @evaluatedAt, @metadata)
    `);
    stmt.run({
      id: decision.id,
      serverId: decision.serverId,
      policyId: decision.policyId,
      ruleId: decision.ruleId,
      verdict: decision.verdict,
      reason: decision.reason,
      findings: JSON.stringify(decision.findings),
      waiverId: decision.waiverId || null,
      evaluatedAt: decision.evaluatedAt,
      metadata: JSON.stringify(decision.metadata),
    });
  }

  // ---------------------------------------------------------------------------
  // Scan Results
  // ---------------------------------------------------------------------------

  insertScanResult(result: ScanResult): void {
    const stmt = this.db.prepare(`
      INSERT INTO scan_results (id, started_at, completed_at, duration, targets, servers_discovered, servers_scanned, risk_score, summary, evidence_bundle_id)
      VALUES (@id, @startedAt, @completedAt, @duration, @targets, @serversDiscovered, @serversScanned, @riskScore, @summary, @evidenceBundleId)
    `);
    stmt.run({
      id: result.id,
      startedAt: result.startedAt,
      completedAt: result.completedAt,
      duration: result.duration,
      targets: JSON.stringify(result.targets),
      serversDiscovered: result.serversDiscovered,
      serversScanned: result.serversScanned,
      riskScore: result.riskScore,
      summary: JSON.stringify(result.summary),
      evidenceBundleId: result.evidenceBundleId || null,
    });
  }

  getScanHistory(limit: number = 50): ScanResult[] {
    const rows = this.db.prepare(
      'SELECT * FROM scan_results ORDER BY completed_at DESC LIMIT ?'
    ).all(limit) as any[];
    return rows.map(row => ({
      id: row.id,
      startedAt: row.started_at,
      completedAt: row.completed_at,
      duration: row.duration,
      targets: JSON.parse(row.targets || '[]'),
      serversDiscovered: row.servers_discovered,
      serversScanned: row.servers_scanned,
      findings: [],
      riskScore: row.risk_score,
      summary: JSON.parse(row.summary || '{}'),
      evidenceBundleId: row.evidence_bundle_id,
    }));
  }

  // ---------------------------------------------------------------------------
  // Evidence Bundles
  // ---------------------------------------------------------------------------

  insertEvidenceBundle(bundle: EvidenceBundle): void {
    const stmt = this.db.prepare(`
      INSERT INTO evidence_bundles (id, server_id, server_version_id, detonation_id, type, findings, artifacts, attestation, created_at, expires_at, metadata)
      VALUES (@id, @serverId, @serverVersionId, @detonationId, @type, @findings, @artifacts, @attestation, @createdAt, @expiresAt, @metadata)
    `);
    stmt.run({
      id: bundle.id,
      serverId: bundle.serverId,
      serverVersionId: bundle.serverVersionId || null,
      detonationId: bundle.detonationId || null,
      type: bundle.type,
      findings: JSON.stringify(bundle.findings),
      artifacts: JSON.stringify(bundle.artifacts),
      attestation: bundle.attestation ? JSON.stringify(bundle.attestation) : null,
      createdAt: bundle.createdAt,
      expiresAt: bundle.expiresAt || null,
      metadata: JSON.stringify(bundle.metadata),
    });
  }

  // ---------------------------------------------------------------------------
  // Trace
  // ---------------------------------------------------------------------------

  insertTrace(trace: Trace): void {
    const stmt = this.db.prepare(`
      INSERT INTO traces (id, detonation_id, server_id, status, started_at, completed_at, duration, process_tree, file_access, network_events, env_access, honeytoken_hits, probe_results, evidence_bundle_id)
      VALUES (@id, @detonationId, @serverId, @status, @startedAt, @completedAt, @duration, @processTree, @fileAccess, @networkEvents, @envAccess, @honeytokenHits, @probeResults, @evidenceBundleId)
    `);
    stmt.run({
      id: trace.id,
      detonationId: trace.detonationId,
      serverId: trace.serverId,
      status: trace.status,
      startedAt: trace.startedAt,
      completedAt: trace.completedAt || null,
      duration: trace.duration || null,
      processTree: JSON.stringify(trace.processTree),
      fileAccess: JSON.stringify(trace.fileAccess),
      networkEvents: JSON.stringify(trace.networkEvents),
      envAccess: JSON.stringify(trace.envAccess),
      honeytokenHits: JSON.stringify(trace.honeytokenHits),
      probeResults: JSON.stringify(trace.probeResults),
      evidenceBundleId: trace.evidenceBundleId || null,
    });
  }

  // ---------------------------------------------------------------------------
  // Audit Log (Immutable)
  // ---------------------------------------------------------------------------

  logAudit(action: string, entityType: string, entityId: string, actor: string = 'system', details: Record<string, unknown> = {}): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_log (action, entity_type, entity_id, actor, details, timestamp)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(action, entityType, entityId, actor, JSON.stringify(details), new Date().toISOString());
  }

  getAuditLog(limit: number = 100, entityType?: string): Array<{
    id: number;
    action: string;
    entityType: string;
    entityId: string;
    actor: string;
    details: Record<string, unknown>;
    timestamp: string;
  }> {
    let query = 'SELECT * FROM audit_log';
    const params: any[] = [];
    if (entityType) {
      query += ' WHERE entity_type = ?';
      params.push(entityType);
    }
    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limit);

    const rows = this.db.prepare(query).all(...params) as any[];
    return rows.map(row => ({
      id: row.id,
      action: row.action,
      entityType: row.entity_type,
      entityId: row.entity_id,
      actor: row.actor,
      details: JSON.parse(row.details || '{}'),
      timestamp: row.timestamp,
    }));
  }

  // ---------------------------------------------------------------------------
  // Statistics
  // ---------------------------------------------------------------------------

  getStats(): {
    totalServers: number;
    totalFindings: number;
    openFindings: number;
    criticalFindings: number;
    highFindings: number;
    totalScans: number;
    totalWaivers: number;
    avgRiskScore: number;
  } {
    const servers = (this.db.prepare('SELECT COUNT(*) as count FROM servers').get() as any).count;
    const findings = (this.db.prepare('SELECT COUNT(*) as count FROM findings').get() as any).count;
    const open = (this.db.prepare("SELECT COUNT(*) as count FROM findings WHERE status = 'open'").get() as any).count;
    const critical = (this.db.prepare("SELECT COUNT(*) as count FROM findings WHERE severity = 'critical'").get() as any).count;
    const high = (this.db.prepare("SELECT COUNT(*) as count FROM findings WHERE severity = 'high'").get() as any).count;
    const scans = (this.db.prepare('SELECT COUNT(*) as count FROM scan_results').get() as any).count;
    const waivers = (this.db.prepare('SELECT COUNT(*) as count FROM waivers WHERE is_active = 1').get() as any).count;
    const avgRisk = (this.db.prepare('SELECT AVG(risk_score) as avg FROM servers WHERE risk_score IS NOT NULL').get() as any).avg || 0;

    return {
      totalServers: servers,
      totalFindings: findings,
      openFindings: open,
      criticalFindings: critical,
      highFindings: high,
      totalScans: scans,
      totalWaivers: waivers,
      avgRiskScore: Math.round(avgRisk * 100) / 100,
    };
  }

  close(): void {
    this.db.close();
  }
}
