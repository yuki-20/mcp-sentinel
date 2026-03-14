// ============================================================================
// Evidence Service — REST API Server
// Evidence store, search, analytics, audit log, signed attestations
// ============================================================================

import express from 'express';
import cors from 'cors';
import { SentinelDB } from '@mcp-sentinel/core';
import type { Finding, Server, Policy, ScanResult } from '@mcp-sentinel/core';

export function createEvidenceServer(db: SentinelDB, port: number = 3001): express.Express {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '50mb' }));

  // ------ Health ------
  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' });
  });

  // ------ Dashboard Stats ------
  app.get('/api/stats', (_req, res) => {
    try {
      const stats = db.getStats();
      res.json(stats);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // ------ Servers ------
  app.get('/api/servers', (_req, res) => {
    try {
      const servers = db.getAllServers();
      res.json(servers);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  app.get('/api/servers/:id', (req, res) => {
    try {
      const server = db.getServer(req.params.id);
      if (!server) return res.status(404).json({ error: 'Server not found' });
      const findings = db.getFindingsForServer(req.params.id);
      res.json({ ...server, findings });
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // ------ Findings ------
  app.get('/api/findings', (req, res) => {
    try {
      let findings: Finding[];
      if (req.query.severity) {
        findings = db.getFindingsBySeverity(req.query.severity as string);
      } else if (req.query.detector) {
        findings = db.getFindingsByDetector(req.query.detector as string);
      } else {
        findings = db.getAllFindings();
      }
      res.json(findings);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // ------ Policies ------
  app.get('/api/policies', (_req, res) => {
    try {
      const policies = db.getActivePolicies();
      res.json(policies);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // ------ Waivers ------
  app.get('/api/waivers', (_req, res) => {
    try {
      const waivers = db.getActiveWaivers();
      res.json(waivers);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // ------ Scan History ------
  app.get('/api/scans', (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const scans = db.getScanHistory(limit);
      res.json(scans);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // ------ Audit Log ------
  app.get('/api/audit', (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const entityType = req.query.entityType as string | undefined;
      const log = db.getAuditLog(limit, entityType);
      res.json(log);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  return app;
}

// Start server if run directly
if (require.main === module) {
  const db = new SentinelDB();
  const port = parseInt(process.env.PORT || '3001');
  const app = createEvidenceServer(db, port);
  app.listen(port, () => {
    console.log(`MCP Sentinel Evidence API running on http://localhost:${port}`);
  });
}
