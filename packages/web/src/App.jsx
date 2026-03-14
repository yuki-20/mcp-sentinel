import { useState, useEffect } from 'react'
import './index.css'

// ============================================================================
// Mock Data — represents real API data from the Evidence service
// ============================================================================

const MOCK_STATS = {
  totalServers: 14,
  totalFindings: 47,
  openFindings: 31,
  criticalFindings: 8,
  highFindings: 12,
  totalScans: 23,
  totalWaivers: 3,
  avgRiskScore: 6.4,
};

const MOCK_SERVERS = [
  { id: 's1', name: 'filesystem', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/home/user'], approvalStatus: 'approved', riskScore: 3.2, authPosture: 'none', findings: 2 },
  { id: 's2', name: 'github', transport: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], approvalStatus: 'pending', riskScore: 7.8, authPosture: 'api-key', findings: 5 },
  { id: 's3', name: 'slack', transport: 'http', command: '', url: 'https://mcp.slack.com/v1', approvalStatus: 'denied', riskScore: 9.1, authPosture: 'oauth', findings: 8 },
  { id: 's4', name: 'database', transport: 'stdio', command: 'node', args: ['server.js'], approvalStatus: 'approved', riskScore: 5.5, authPosture: 'api-key', findings: 3 },
  { id: 's5', name: 'kubernetes', transport: 'stdio', command: 'kubectl-mcp', args: ['serve'], approvalStatus: 'pending', riskScore: 8.9, authPosture: 'bearer-token', findings: 7 },
  { id: 's6', name: 'web-browser', transport: 'stdio', command: 'npx', args: ['-y', '@anthropic/mcp-browser'], approvalStatus: 'approved', riskScore: 4.1, authPosture: 'none', findings: 2 },
  { id: 's7', name: 'analytics-tool', transport: 'http', command: '', url: 'https://analytics.internal/mcp', approvalStatus: 'pending', riskScore: 6.7, authPosture: 'none', findings: 4 },
];

const MOCK_FINDINGS = [
  { id: 'f1', serverId: 's2', detector: 'secret-scanner', title: 'GitHub Token in environment', severity: 'critical', confidence: 0.95, status: 'open', description: 'A GitHub personal access token was found in the server environment configuration.', remediation: 'Use a secret manager instead of hardcoding tokens.' },
  { id: 'f2', serverId: 's3', detector: 'auth-posture', title: 'Remote server with weak auth', severity: 'critical', confidence: 0.9, status: 'open', description: 'HTTP transport server without proper OAuth configuration.', remediation: 'Configure OAuth 2.0 per MCP 2025-11-25 spec.' },
  { id: 'f3', serverId: 's5', detector: 'command-injection', title: 'Shell interpolation in kubectl wrapper', severity: 'critical', confidence: 0.85, status: 'open', description: 'User input passed unsafely to shell execution in the kubectl MCP wrapper.', remediation: 'Use parameterized execution (execFile) instead of shell interpolation.' },
  { id: 'f4', serverId: 's3', detector: 'network-exfiltration', title: 'Slack unfurl data exfiltration', severity: 'high', confidence: 0.8, status: 'open', description: 'Slack MCP server can leak data through automatic link unfurling.', remediation: 'Disable automatic link unfurling or sanitize URLs before posting.' },
  { id: 'f5', serverId: 's5', detector: 'startup-command', title: 'Shell wrapper startup command', severity: 'high', confidence: 0.85, status: 'open', description: 'Server uses a shell binary as its command, increasing the attack surface.', remediation: 'Use a direct binary path instead of shell wrapper.' },
  { id: 'f6', serverId: 's2', detector: 'dependency-risk', title: 'Vulnerable dependency detected', severity: 'high', confidence: 0.7, status: 'open', description: 'Package has a dependency with known CVE-2025-12345.', remediation: 'Update the vulnerable dependency to the latest patched version.' },
  { id: 'f7', serverId: 's7', detector: 'ssrf', title: 'Internal URL in server endpoint', severity: 'high', confidence: 0.9, status: 'open', description: 'Server URL points to an internal network address.', remediation: 'Do not use internal network addresses for MCP server endpoints.' },
  { id: 'f8', serverId: 's1', detector: 'path-traversal', title: 'Unrestricted file system access', severity: 'medium', confidence: 0.75, status: 'open', description: 'Filesystem server has access to broad directory paths.', remediation: 'Restrict file system access to specific directories.' },
  { id: 'f9', serverId: 's4', detector: 'secret-scanner', title: 'Database password in env', severity: 'medium', confidence: 0.8, status: 'waived', description: 'Database connection string with embedded password.', remediation: 'Use connection pooling with IAM authentication.' },
  { id: 'f10', serverId: 's6', detector: 'capability-surface', title: 'Browser has broad capabilities', severity: 'low', confidence: 0.6, status: 'open', description: 'Browser MCP server exposes navigation, screenshot, and input tools.', remediation: 'Review and restrict to necessary capabilities only.' },
];

const MOCK_POLICIES = [
  { id: 'p1', name: 'Strict Security', bundle: 'strict', description: 'Blocks most risks, requires evidence for write-capable tools', isActive: false, rulesCount: 6 },
  { id: 'p2', name: 'Standard Security', bundle: 'standard', description: 'Blocks critical and high risks, reviews medium', isActive: true, rulesCount: 4 },
  { id: 'p3', name: 'Permissive Security', bundle: 'permissive', description: 'Only blocks critical severity findings', isActive: false, rulesCount: 1 },
];

const MOCK_SCAN_HISTORY = [
  { id: 'sc1', date: '2026-03-15T01:20:00Z', servers: 14, findings: 47, riskScore: 6.4, duration: 1250 },
  { id: 'sc2', date: '2026-03-14T18:00:00Z', servers: 12, findings: 42, riskScore: 6.8, duration: 980 },
  { id: 'sc3', date: '2026-03-13T12:00:00Z', servers: 12, findings: 39, riskScore: 7.1, duration: 1100 },
  { id: 'sc4', date: '2026-03-12T09:00:00Z', servers: 10, findings: 35, riskScore: 7.5, duration: 890 },
  { id: 'sc5', date: '2026-03-11T15:00:00Z', servers: 10, findings: 33, riskScore: 7.8, duration: 920 },
];

const MOCK_AUDIT_LOG = [
  { id: 1, action: 'scan', entity: 'scan_result', actor: 'cli', timestamp: '2026-03-15T01:20:00Z', details: '14 servers, 47 findings' },
  { id: 2, action: 'policy_eval', entity: 'policy', actor: 'system', timestamp: '2026-03-15T01:20:02Z', details: 'Standard bundle: 3 denied, 2 review' },
  { id: 3, action: 'waiver_created', entity: 'waiver', actor: 'yuki', timestamp: '2026-03-14T16:30:00Z', details: 'Database password waived until 2026-04-14' },
  { id: 4, action: 'server_approved', entity: 'server', actor: 'yuki', timestamp: '2026-03-14T14:00:00Z', details: 'filesystem server approved' },
  { id: 5, action: 'scan', entity: 'scan_result', actor: 'github-action', timestamp: '2026-03-14T18:00:00Z', details: '12 servers, 42 findings' },
];

// ============================================================================
// Components
// ============================================================================

// --- Severity Badge ---
function SeverityBadge({ severity }) {
  return <span className={`severity-badge ${severity}`}>{severity}</span>;
}

// --- Status Dot ---
function StatusDot({ status }) {
  return <span className={`status-dot ${status}`} title={status}></span>;
}

// --- Risk Score Color ---
function riskColor(score) {
  if (score >= 9) return 'var(--severity-critical)';
  if (score >= 7) return 'var(--severity-high)';
  if (score >= 4) return 'var(--severity-medium)';
  if (score >= 2) return 'var(--severity-low)';
  return 'var(--accent-green)';
}

// ============================================================================
// Pages
// ============================================================================

// --- 1. Posture Overview ---
function PostureOverview() {
  const severityCounts = { critical: 8, high: 12, medium: 11, low: 9, info: 7 };
  const maxCount = Math.max(...Object.values(severityCounts));

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Posture Overview</h2>
        <p>Security posture across all discovered MCP servers</p>
      </div>

      <div className="stats-grid stagger-children">
        <div className="stat-card critical animate-fade-in">
          <div className="stat-icon">🔴</div>
          <div className="stat-value">{MOCK_STATS.criticalFindings}</div>
          <div className="stat-label">Critical Findings</div>
        </div>
        <div className="stat-card high animate-fade-in">
          <div className="stat-icon">🟠</div>
          <div className="stat-value" style={{color: 'var(--severity-high)'}}>{MOCK_STATS.highFindings}</div>
          <div className="stat-label">High Findings</div>
        </div>
        <div className="stat-card animate-fade-in">
          <div className="stat-icon">🛡️</div>
          <div className="stat-value" style={{color: 'var(--accent-cyan)'}}>{MOCK_STATS.totalServers}</div>
          <div className="stat-label">Total Servers</div>
        </div>
        <div className="stat-card animate-fade-in">
          <div className="stat-icon">📊</div>
          <div className="stat-value" style={{color: riskColor(MOCK_STATS.avgRiskScore)}}>{MOCK_STATS.avgRiskScore.toFixed(1)}</div>
          <div className="stat-label">Avg Risk Score</div>
        </div>
        <div className="stat-card animate-fade-in">
          <div className="stat-icon">🔍</div>
          <div className="stat-value" style={{color: 'var(--accent-purple)'}}>{MOCK_STATS.totalScans}</div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card success animate-fade-in">
          <div className="stat-icon">📋</div>
          <div className="stat-value">{MOCK_STATS.totalWaivers}</div>
          <div className="stat-label">Active Waivers</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <span className="card-title">Findings by Severity</span>
          </div>
          <div className="bar-chart">
            {Object.entries(severityCounts).map(([sev, count]) => (
              <div className="bar-row" key={sev}>
                <span className="bar-label">{sev}</span>
                <div className="bar-track">
                  <div className={`bar-fill ${sev}`} style={{width: `${(count / maxCount) * 100}%`}}></div>
                </div>
                <span className="bar-count">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-title">Risk Score Trend</span>
          </div>
          <div style={{display: 'flex', alignItems: 'flex-end', gap: '12px', height: '200px', padding: '20px 0'}}>
            {MOCK_SCAN_HISTORY.slice().reverse().map((scan, i) => (
              <div key={scan.id} style={{flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px'}}>
                <span style={{fontSize: '12px', color: riskColor(scan.riskScore), fontWeight: 700}}>{scan.riskScore}</span>
                <div style={{
                  width: '100%',
                  height: `${scan.riskScore * 18}px`,
                  background: `linear-gradient(180deg, ${riskColor(scan.riskScore)}, transparent)`,
                  borderRadius: '6px 6px 0 0',
                  opacity: 0.7 + (i * 0.06),
                  transition: 'height 0.5s ease',
                }}></div>
                <span style={{fontSize: '10px', color: 'var(--text-muted)'}}>
                  {new Date(scan.date).toLocaleDateString('en-US', {month: 'short', day: 'numeric'})}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="card" style={{marginTop: 'var(--space-lg)'}}>
        <div className="card-header">
          <span className="card-title">Top Risks</span>
        </div>
        <table className="data-table">
          <thead>
            <tr><th>Severity</th><th>Finding</th><th>Server</th><th>Detector</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            {MOCK_FINDINGS.filter(f => f.status === 'open').slice(0, 5).map(f => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td style={{color: 'var(--text-primary)', fontWeight: 500}}>{f.title}</td>
                <td>{MOCK_SERVERS.find(s => s.id === f.serverId)?.name}</td>
                <td><span style={{color: 'var(--accent-purple)'}}>{f.detector}</span></td>
                <td>{(f.confidence * 100).toFixed(0)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- 2. Server Inventory ---
function ServerInventory() {
  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Server Inventory</h2>
        <p>All discovered MCP servers and their security posture</p>
      </div>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Status</th><th>Name</th><th>Transport</th><th>Auth</th><th>Risk</th><th>Findings</th><th>Approval</th></tr>
          </thead>
          <tbody>
            {MOCK_SERVERS.map(s => (
              <tr key={s.id}>
                <td><StatusDot status={s.approvalStatus} /></td>
                <td style={{color: 'var(--text-primary)', fontWeight: 600}}>{s.name}</td>
                <td><span style={{
                  padding: '2px 8px', borderRadius: '4px', fontSize: '12px',
                  background: s.transport === 'http' ? 'rgba(139,92,246,0.15)' : 'rgba(6,182,212,0.15)',
                  color: s.transport === 'http' ? 'var(--accent-purple)' : 'var(--accent-cyan)',
                }}>{s.transport}</span></td>
                <td>{s.authPosture}</td>
                <td style={{color: riskColor(s.riskScore), fontWeight: 700}}>{s.riskScore.toFixed(1)}</td>
                <td>{s.findings}</td>
                <td><span style={{
                  padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 600,
                  background: s.approvalStatus === 'approved' ? 'rgba(16,185,129,0.15)' :
                    s.approvalStatus === 'denied' ? 'rgba(239,68,68,0.15)' : 'rgba(245,158,11,0.15)',
                  color: s.approvalStatus === 'approved' ? 'var(--accent-green)' :
                    s.approvalStatus === 'denied' ? 'var(--accent-red)' : 'var(--accent-yellow)',
                }}>{s.approvalStatus}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- 3. Findings ---
function FindingsPage() {
  const [filter, setFilter] = useState('all');
  const filtered = filter === 'all' ? MOCK_FINDINGS : MOCK_FINDINGS.filter(f => f.severity === filter);

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Findings</h2>
        <p>Security findings across all MCP servers</p>
      </div>
      <div style={{display: 'flex', gap: '8px', marginBottom: '20px'}}>
        {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
          <button key={sev} className={`btn ${filter === sev ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setFilter(sev)} style={{textTransform: 'capitalize'}}>
            {sev} {sev !== 'all' ? `(${MOCK_FINDINGS.filter(f => f.severity === sev).length})` : `(${MOCK_FINDINGS.length})`}
          </button>
        ))}
      </div>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr><th>Severity</th><th>Title</th><th>Server</th><th>Detector</th><th>Status</th><th>Confidence</th></tr>
          </thead>
          <tbody>
            {filtered.map(f => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td>
                  <div style={{color: 'var(--text-primary)', fontWeight: 500}}>{f.title}</div>
                  <div style={{color: 'var(--text-muted)', fontSize: '12px', marginTop: '4px'}}>{f.description}</div>
                </td>
                <td>{MOCK_SERVERS.find(s => s.id === f.serverId)?.name}</td>
                <td style={{color: 'var(--accent-purple)'}}>{f.detector}</td>
                <td><span style={{
                  padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600,
                  background: f.status === 'open' ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                  color: f.status === 'open' ? 'var(--accent-red)' : 'var(--accent-green)',
                }}>{f.status}</span></td>
                <td>{(f.confidence * 100).toFixed(0)}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- 4. Server Detail ---
function ServerDetail() {
  const server = MOCK_SERVERS[1]; // Show github server
  const findings = MOCK_FINDINGS.filter(f => f.serverId === server.id);

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Server: {server.name}</h2>
        <p>Detailed security analysis for this MCP server</p>
      </div>
      <div className="grid-3" style={{marginBottom: 'var(--space-lg)'}}>
        <div className="stat-card">
          <div className="stat-icon">📡</div>
          <div className="stat-value" style={{fontSize: '20px', color: 'var(--accent-cyan)'}}>{server.transport}</div>
          <div className="stat-label">Transport</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">🔐</div>
          <div className="stat-value" style={{fontSize: '20px', color: 'var(--accent-purple)'}}>{server.authPosture}</div>
          <div className="stat-label">Auth Posture</div>
        </div>
        <div className="stat-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value" style={{fontSize: '20px', color: riskColor(server.riskScore)}}>{server.riskScore.toFixed(1)}</div>
          <div className="stat-label">Risk Score</div>
        </div>
      </div>
      <div className="card" style={{marginBottom: 'var(--space-lg)'}}>
        <div className="card-header"><span className="card-title">Configuration</span></div>
        <pre style={{background: 'rgba(0,0,0,0.3)', padding: '16px', borderRadius: '8px', fontSize: '13px', color: 'var(--accent-cyan)', overflow: 'auto'}}>
{JSON.stringify({name: server.name, command: server.command, args: server.args, transport: server.transport, authPosture: server.authPosture}, null, 2)}
        </pre>
      </div>
      <div className="card">
        <div className="card-header"><span className="card-title">Findings ({findings.length})</span></div>
        <table className="data-table">
          <thead><tr><th>Severity</th><th>Finding</th><th>Detector</th><th>Status</th></tr></thead>
          <tbody>
            {findings.map(f => (
              <tr key={f.id}>
                <td><SeverityBadge severity={f.severity} /></td>
                <td style={{color: 'var(--text-primary)', fontWeight: 500}}>{f.title}<br/><span style={{color: 'var(--text-muted)', fontSize: '12px'}}>{f.remediation}</span></td>
                <td style={{color: 'var(--accent-purple)'}}>{f.detector}</td>
                <td>{f.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- 5. Policy Manager ---
function PolicyManager() {
  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Policy Manager</h2>
        <p>Create, edit, and manage security policies</p>
      </div>
      <div style={{display: 'flex', gap: 'var(--space-md)', marginBottom: 'var(--space-lg)'}}>
        {MOCK_POLICIES.map(p => (
          <div key={p.id} className="card" style={{flex: 1, cursor: 'pointer', border: p.isActive ? '1px solid var(--accent-cyan)' : undefined}}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px'}}>
              <span style={{fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)'}}>{p.name}</span>
              {p.isActive && <span style={{padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 700, background: 'rgba(6,182,212,0.15)', color: 'var(--accent-cyan)'}}>ACTIVE</span>}
            </div>
            <p style={{color: 'var(--text-secondary)', fontSize: '13px', marginBottom: '12px'}}>{p.description}</p>
            <div style={{display: 'flex', justifyContent: 'space-between'}}>
              <span style={{color: 'var(--text-muted)', fontSize: '12px'}}>{p.rulesCount} rules</span>
              <span style={{color: 'var(--accent-purple)', fontSize: '12px', fontWeight: 600}}>{p.bundle}</span>
            </div>
          </div>
        ))}
      </div>
      <div className="card">
        <div className="card-header"><span className="card-title">Policy Rules — Standard Bundle</span></div>
        <table className="data-table">
          <thead><tr><th>Rule</th><th>Action</th><th>Severity</th><th>Description</th></tr></thead>
          <tbody>
            <tr><td style={{fontWeight: 500, color: 'var(--text-primary)'}}>Deny critical severity</td><td><span style={{color: 'var(--accent-red)', fontWeight: 700}}>DENY</span></td><td><SeverityBadge severity="critical"/></td><td>Block any server with critical findings</td></tr>
            <tr><td style={{fontWeight: 500, color: 'var(--text-primary)'}}>Review high severity</td><td><span style={{color: 'var(--accent-yellow)', fontWeight: 700}}>REVIEW</span></td><td><SeverityBadge severity="high"/></td><td>Require review for high severity findings</td></tr>
            <tr><td style={{fontWeight: 500, color: 'var(--text-primary)'}}>Deny command injection</td><td><span style={{color: 'var(--accent-red)', fontWeight: 700}}>DENY</span></td><td><SeverityBadge severity="critical"/></td><td>Block servers with command injection vulnerabilities</td></tr>
            <tr><td style={{fontWeight: 500, color: 'var(--text-primary)'}}>Deny token passthrough</td><td><span style={{color: 'var(--accent-red)', fontWeight: 700}}>DENY</span></td><td><SeverityBadge severity="critical"/></td><td>Block servers forwarding user tokens</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- 6. Evidence Explorer ---
function EvidenceExplorer() {
  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Evidence Explorer</h2>
        <p>Browse evidence bundles, traces, and detonation artifacts</p>
      </div>
      <div className="card" style={{marginBottom: 'var(--space-lg)'}}>
        <div className="card-header"><span className="card-title">Scan History</span></div>
        <table className="data-table">
          <thead><tr><th>Date</th><th>Servers</th><th>Findings</th><th>Risk Score</th><th>Duration</th><th>Actions</th></tr></thead>
          <tbody>
            {MOCK_SCAN_HISTORY.map(s => (
              <tr key={s.id}>
                <td style={{color: 'var(--text-primary)'}}>{new Date(s.date).toLocaleString()}</td>
                <td>{s.servers}</td>
                <td>{s.findings}</td>
                <td style={{color: riskColor(s.riskScore), fontWeight: 700}}>{s.riskScore.toFixed(1)}</td>
                <td>{s.duration}ms</td>
                <td><button className="btn btn-secondary" style={{fontSize: '12px', padding: '4px 8px'}}>📦 View Bundle</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <div className="card-header"><span className="card-title">Audit Log</span></div>
        <div style={{display: 'flex', flexDirection: 'column', gap: '8px'}}>
          {MOCK_AUDIT_LOG.map(entry => (
            <div key={entry.id} style={{display: 'flex', alignItems: 'center', gap: '16px', padding: '8px 12px', background: 'rgba(0,0,0,0.2)', borderRadius: '8px'}}>
              <span style={{color: 'var(--text-muted)', fontSize: '12px', width: '180px'}}>{new Date(entry.timestamp).toLocaleString()}</span>
              <span style={{color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '13px', width: '120px'}}>{entry.action}</span>
              <span style={{color: 'var(--text-secondary)', fontSize: '13px', flex: 1}}>{entry.details}</span>
              <span style={{color: 'var(--text-muted)', fontSize: '12px'}}>{entry.actor}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// --- 7. Detonation Console ---
function DetonationConsole() {
  const [isDetonating, setIsDetonating] = useState(false);
  const [progress, setProgress] = useState(0);

  const startDetonation = () => {
    setIsDetonating(true);
    setProgress(0);
    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 100) { clearInterval(interval); setIsDetonating(false); return 100; }
        return p + Math.random() * 15;
      });
    }, 300);
  };

  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Detonation Console</h2>
        <p>Runtime detonation sandbox for MCP servers</p>
      </div>
      <div className="grid-2" style={{marginBottom: 'var(--space-lg)'}}>
        <div className="card">
          <div className="card-header"><span className="card-title">Quick Detonate</span></div>
          <p style={{color: 'var(--text-secondary)', fontSize: '14px', marginBottom: '16px'}}>
            Select a server to detonate in an isolated sandbox with honeytokens, network monitoring, and protocol probes.
          </p>
          <select style={{width: '100%', padding: '10px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--bg-glass-border)', borderRadius: '8px', color: 'var(--text-primary)', fontSize: '14px', marginBottom: '12px'}}>
            {MOCK_SERVERS.map(s => <option key={s.id} value={s.id}>🛡️ {s.name} ({s.transport})</option>)}
          </select>
          <div style={{display: 'flex', gap: '8px'}}>
            <button className="btn btn-danger" onClick={startDetonation} disabled={isDetonating}>
              💥 {isDetonating ? 'Detonating...' : 'Start Detonation'}
            </button>
          </div>
          {isDetonating && (
            <div style={{marginTop: '16px'}}>
              <div style={{height: '6px', background: 'rgba(255,255,255,0.06)', borderRadius: '3px', overflow: 'hidden'}}>
                <div style={{height: '100%', width: `${Math.min(progress, 100)}%`, background: 'var(--gradient-danger)', borderRadius: '3px', transition: 'width 0.3s'}}></div>
              </div>
              <div style={{display: 'flex', justifyContent: 'space-between', marginTop: '8px', color: 'var(--text-muted)', fontSize: '12px'}}>
                <span>{progress < 30 ? '🔧 Setting up sandbox...' : progress < 60 ? '🔍 Running probes...' : progress < 90 ? '📡 Capturing telemetry...' : '✅ Building evidence bundle...'}</span>
                <span>{Math.min(Math.round(progress), 100)}%</span>
              </div>
            </div>
          )}
          {progress >= 100 && (
            <div style={{marginTop: '16px', padding: '12px', background: 'rgba(16,185,129,0.1)', borderRadius: '8px', border: '1px solid rgba(16,185,129,0.2)'}}>
              <span style={{color: 'var(--accent-green)', fontWeight: 700}}>✅ Detonation complete</span>
              <div style={{color: 'var(--text-secondary)', fontSize: '13px', marginTop: '4px'}}>
                Duration: 2.3s • Probes: 6 • Honeytoken hits: 0 • Evidence bundle signed
              </div>
            </div>
          )}
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Sandbox Features</span></div>
          <div style={{display: 'flex', flexDirection: 'column', gap: '12px'}}>
            {[
              {icon: '🍯', name: 'Honeytokens', desc: 'Canary API keys, files, URLs, metadata endpoints'},
              {icon: '📁', name: 'Synthetic Workspace', desc: 'Fake repos, docs, credentials to bait malicious behavior'},
              {icon: '🌐', name: 'Network Control', desc: 'DNS sinkhole, HTTP proxy, domain allowlists, pcap capture'},
              {icon: '📊', name: 'Telemetry', desc: 'Process trees, file I/O, env access, child processes'},
              {icon: '🧪', name: 'Protocol Probes', desc: 'Tool fuzzing, path traversal, injection, schema drift'},
              {icon: '📜', name: 'Evidence Bundles', desc: 'Normalized JSON, traces, signed attestations'},
            ].map(f => (
              <div key={f.name} style={{display: 'flex', gap: '12px', alignItems: 'flex-start'}}>
                <span style={{fontSize: '20px'}}>{f.icon}</span>
                <div>
                  <div style={{fontWeight: 600, color: 'var(--text-primary)', fontSize: '14px'}}>{f.name}</div>
                  <div style={{color: 'var(--text-muted)', fontSize: '12px'}}>{f.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// --- 8. Settings ---
function SettingsPage() {
  return (
    <div className="animate-fade-in">
      <div className="page-header">
        <h2>Settings & Admin</h2>
        <p>Platform configuration and administration</p>
      </div>
      <div className="grid-2">
        <div className="card">
          <div className="card-header"><span className="card-title">General</span></div>
          <div style={{display:'flex',flexDirection:'column',gap:'16px'}}>
            <div>
              <label style={{color:'var(--text-secondary)',fontSize:'13px',display:'block',marginBottom:'4px'}}>Database Path</label>
              <input value=".sentinel/sentinel.db" readOnly style={{width:'100%',padding:'8px 12px',background:'rgba(0,0,0,0.3)',border:'1px solid var(--bg-glass-border)',borderRadius:'8px',color:'var(--text-primary)',fontSize:'13px'}} />
            </div>
            <div>
              <label style={{color:'var(--text-secondary)',fontSize:'13px',display:'block',marginBottom:'4px'}}>Default Policy Bundle</label>
              <select style={{width:'100%',padding:'8px 12px',background:'rgba(0,0,0,0.3)',border:'1px solid var(--bg-glass-border)',borderRadius:'8px',color:'var(--text-primary)',fontSize:'13px'}}>
                <option>Standard</option><option>Strict</option><option>Permissive</option>
              </select>
            </div>
            <div>
              <label style={{color:'var(--text-secondary)',fontSize:'13px',display:'block',marginBottom:'4px'}}>Evidence Retention (days)</label>
              <input defaultValue="90" type="number" style={{width:'100%',padding:'8px 12px',background:'rgba(0,0,0,0.3)',border:'1px solid var(--bg-glass-border)',borderRadius:'8px',color:'var(--text-primary)',fontSize:'13px'}} />
            </div>
          </div>
        </div>
        <div className="card">
          <div className="card-header"><span className="card-title">Integrations</span></div>
          <div style={{display:'flex',flexDirection:'column',gap:'12px'}}>
            {[
              {name: 'GitHub Actions', status: 'configured', icon: '🐙'},
              {name: 'SIEM (Splunk)', status: 'not configured', icon: '📊'},
              {name: 'Jira', status: 'not configured', icon: '📋'},
              {name: 'Slack Alerts', status: 'configured', icon: '💬'},
              {name: 'Private Registry', status: 'not configured', icon: '📦'},
            ].map(i => (
              <div key={i.name} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 12px',background:'rgba(0,0,0,0.2)',borderRadius:'8px'}}>
                <div style={{display:'flex',alignItems:'center',gap:'10px'}}>
                  <span>{i.icon}</span>
                  <span style={{fontWeight:500,color:'var(--text-primary)',fontSize:'14px'}}>{i.name}</span>
                </div>
                <span style={{
                  padding:'2px 8px',borderRadius:'4px',fontSize:'11px',fontWeight:600,
                  background: i.status === 'configured' ? 'rgba(16,185,129,0.15)' : 'rgba(100,116,139,0.15)',
                  color: i.status === 'configured' ? 'var(--accent-green)' : 'var(--text-muted)',
                }}>{i.status}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Main App
// ============================================================================

function App() {
  const [currentPage, setCurrentPage] = useState('overview');

  const navItems = [
    { id: 'overview', icon: '📊', label: 'Posture Overview' },
    { id: 'inventory', icon: '🛡️', label: 'Server Inventory' },
    { id: 'findings', icon: '🔍', label: 'Findings' },
    { id: 'detail', icon: '📋', label: 'Server Detail' },
    { id: 'policies', icon: '📜', label: 'Policy Manager' },
    { id: 'evidence', icon: '📦', label: 'Evidence Explorer' },
    { id: 'detonation', icon: '💥', label: 'Detonation Console' },
    { id: 'settings', icon: '⚙️', label: 'Settings & Admin' },
  ];

  const pages = {
    overview: <PostureOverview />,
    inventory: <ServerInventory />,
    findings: <FindingsPage />,
    detail: <ServerDetail />,
    policies: <PolicyManager />,
    evidence: <EvidenceExplorer />,
    detonation: <DetonationConsole />,
    settings: <SettingsPage />,
  };

  return (
    <div className="app-layout">
      <nav className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🛡️</div>
          <h1>MCP Sentinel</h1>
        </div>
        <div className="sidebar-nav">
          <div className="nav-section">Security</div>
          {navItems.slice(0, 4).map(item => (
            <button key={item.id}
              className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
              onClick={() => setCurrentPage(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
          <div className="nav-section">Governance</div>
          {navItems.slice(4, 7).map(item => (
            <button key={item.id}
              className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
              onClick={() => setCurrentPage(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
          <div className="nav-section">System</div>
          {navItems.slice(7).map(item => (
            <button key={item.id}
              className={`nav-item ${currentPage === item.id ? 'active' : ''}`}
              onClick={() => setCurrentPage(item.id)}>
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </nav>
      <main className="main-content">
        {pages[currentPage]}
      </main>
    </div>
  );
}

export default App
