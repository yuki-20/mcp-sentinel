#!/usr/bin/env node
// ============================================================================
// MCP Sentinel CLI — Full Command Suite
// sentinel scan | discover | analyze | detonate | policy | evidence | registry | report
// ============================================================================

import { Command } from 'commander';
import chalk from 'chalk';
import Table from 'cli-table3';
import ora from 'ora';
import * as fs from 'fs';
import * as path from 'path';
import {
  SentinelDB, ScanResult, Severity, FindingStatus,
  createId, createTimestamp, buildScanSummary, formatJSON,
  formatSARIF, formatText,
} from '@mcp-sentinel/core';
import { discoverAllClients, ClaudeDesktopParser, CursorParser, VSCodeParser, ClaudeCodeParser } from '@mcp-sentinel/collector';
import { ScannerEngine } from '@mcp-sentinel/scanner';
import type { DetectorContext } from '@mcp-sentinel/scanner';
import { PolicyEngine, getAllPolicyBundles } from '@mcp-sentinel/policy';
import { DetonationScheduler } from '@mcp-sentinel/runner';

const program = new Command();

// ---------------------------------------------------------------------------
// ASCII Banner
// ---------------------------------------------------------------------------

function printBanner(): void {
  console.log(chalk.cyan.bold(`
  ╔═══════════════════════════════════════════════════════════╗
  ║                                                           ║
  ║   ███╗   ███╗ ██████╗██████╗     ███████╗███████╗███╗  ██╗║
  ║   ████╗ ████║██╔════╝██╔══██╗    ██╔════╝██╔════╝████╗ ██║║
  ║   ██╔████╔██║██║     ██████╔╝    ███████╗█████╗  ██╔██╗██║║
  ║   ██║╚██╔╝██║██║     ██╔═══╝     ╚════██║██╔══╝  ██║╚████║║
  ║   ██║ ╚═╝ ██║╚██████╗██║         ███████║███████╗██║ ╚███║║
  ║   ╚═╝     ╚═╝ ╚═════╝╚═╝         ╚══════╝╚══════╝╚═╝  ╚══╝║
  ║                                                           ║
  ║   MCP Security Posture Management & Detonation Platform   ║
  ║   v1.0.0                                                  ║
  ╚═══════════════════════════════════════════════════════════╝
  `));
}

// ---------------------------------------------------------------------------
// Helper: Severity colors
// ---------------------------------------------------------------------------

function colorSeverity(sev: string): string {
  switch (sev) {
    case 'critical': return chalk.bgRed.white.bold(` ${sev.toUpperCase()} `);
    case 'high': return chalk.red.bold(sev.toUpperCase());
    case 'medium': return chalk.yellow(sev.toUpperCase());
    case 'low': return chalk.cyan(sev);
    case 'info': return chalk.gray(sev);
    default: return sev;
  }
}

// ---------------------------------------------------------------------------
// sentinel scan
// ---------------------------------------------------------------------------

program
  .name('sentinel')
  .description('MCP Security Posture Management & Detonation Platform')
  .version('1.0.0');

program
  .command('scan')
  .description('Full security scan of local MCP configurations')
  .option('-p, --path <path>', 'Path to a specific MCP config file')
  .option('-d, --directory <dir>', 'Directory to scan for MCP configs')
  .option('-f, --format <format>', 'Output format: text, json, sarif', 'text')
  .option('-o, --output <file>', 'Output file path')
  .option('--policy <bundle>', 'Policy bundle: strict, standard, permissive', 'standard')
  .option('--verbose', 'Verbose output')
  .action(async (opts) => {
    printBanner();
    const spinner = ora('Discovering MCP servers...').start();

    try {
      const db = new SentinelDB();
      const startedAt = createTimestamp();

      // Discovery
      const customPaths = opts.path ? [opts.path] : undefined;
      const parseResults = discoverAllClients(customPaths);

      const allServers = parseResults.flatMap(r => r.servers);
      spinner.succeed(`Found ${allServers.length} MCP server(s) across ${parseResults.length} client(s)`);

      if (allServers.length === 0) {
        console.log(chalk.yellow('\n  No MCP servers found. Try specifying a config path with --path'));
        db.close();
        return;
      }

      // Store servers
      for (const server of allServers) {
        db.upsertServer(server);
      }

      // Scan each server
      const scanner = new ScannerEngine();
      const allFindings: any[] = [];
      const scanSpinner = ora('Running security analysis...').start();

      for (const server of allServers) {
        const ctx: DetectorContext = {
          server,
          configContent: opts.path ? fs.readFileSync(opts.path, 'utf-8') : undefined,
        };

        const findings = scanner.scan(ctx);
        allFindings.push(...findings);

        // Store findings
        for (const finding of findings) {
          db.insertFinding(finding);
        }

        // Update server risk
        const { aggregateServerRisk } = require('@mcp-sentinel/core');
        const risk = aggregateServerRisk(findings, server);
        server.riskScore = risk.adjusted;
        db.upsertServer(server);
      }

      scanSpinner.succeed(`Analysis complete: ${allFindings.length} finding(s) detected`);

      // Policy evaluation
      const policySpinner = ora('Evaluating policies...').start();
      const policyEngine = new PolicyEngine();
      const bundles = getAllPolicyBundles();
      const selectedBundle = bundles.find(b => b.bundle === opts.policy) || bundles[1];
      policyEngine.loadPolicies([selectedBundle]);

      let totalDecisions = 0;
      for (const server of allServers) {
        const serverFindings = allFindings.filter((f: any) => f.serverId === server.id);
        const decisions = policyEngine.evaluate(server, serverFindings);
        totalDecisions += decisions.length;
        for (const decision of decisions) {
          db.insertDecision(decision);
        }
      }

      const verdicts = policyEngine.getVerdictSummary(policyEngine.getDecisions());
      policySpinner.succeed(
        `Policy evaluation: ${chalk.green(`${verdicts.allowed} allowed`)}, ${chalk.red(`${verdicts.denied} denied`)}, ${chalk.yellow(`${verdicts.review} review`)}`
      );

      // Build scan result
      const completedAt = createTimestamp();
      const summary = buildScanSummary(allFindings);

      const scanResult: ScanResult = {
        id: createId(),
        startedAt,
        completedAt,
        duration: new Date(completedAt).getTime() - new Date(startedAt).getTime(),
        targets: [],
        serversDiscovered: allServers.length,
        serversScanned: allServers.length,
        findings: allFindings,
        riskScore: Math.max(...allServers.map(s => s.riskScore || 0), 0),
        summary,
      };

      db.insertScanResult(scanResult);
      db.logAudit('scan', 'scan_result', scanResult.id, 'cli', { servers: allServers.length, findings: allFindings.length });

      // Format output
      let output: string;
      switch (opts.format) {
        case 'json':
          output = formatJSON(scanResult);
          break;
        case 'sarif':
          output = formatSARIF(scanResult);
          break;
        default:
          output = formatText(scanResult);
      }

      if (opts.output) {
        fs.writeFileSync(opts.output, output);
        console.log(chalk.green(`\n  Report saved to ${opts.output}`));
      } else {
        console.log(output);
      }

      db.close();
    } catch (e: any) {
      spinner.fail(`Scan failed: ${e.message}`);
      if (opts.verbose) console.error(e);
    }
  });

// ---------------------------------------------------------------------------
// sentinel discover
// ---------------------------------------------------------------------------

program
  .command('discover')
  .description('Discover and inventory all local MCP servers')
  .option('-p, --path <path>', 'Path to a specific config file')
  .action(async (opts) => {
    printBanner();
    const spinner = ora('Scanning for MCP configurations...').start();

    try {
      const parseResults = discoverAllClients(opts.path ? [opts.path] : undefined);
      spinner.succeed('Discovery complete');

      if (parseResults.length === 0) {
        console.log(chalk.yellow('\n  No MCP clients found on this system.'));
        return;
      }

      for (const result of parseResults) {
        console.log(chalk.bold.cyan(`\n  📋 ${result.client.name}`));
        console.log(chalk.dim(`     Config: ${result.client.configPath}`));

        if (result.servers.length === 0) {
          console.log(chalk.dim('     No servers configured'));
          continue;
        }

        const table = new Table({
          head: ['Name', 'Transport', 'Command', 'Auth', 'Env Vars'],
          style: { head: ['cyan'] },
        });

        for (const server of result.servers) {
          table.push([
            server.name,
            server.transport,
            server.command ? `${server.command} ${(server.args || []).slice(0, 2).join(' ')}` : server.url || '-',
            (server.metadata?.authPosture as string) || 'unknown',
            Object.keys(server.env || {}).length.toString(),
          ]);
        }

        console.log(table.toString());
      }

      const totalServers = parseResults.reduce((sum, r) => sum + r.servers.length, 0);
      console.log(chalk.bold.green(`\n  Total: ${totalServers} server(s) across ${parseResults.length} client(s)\n`));
    } catch (e: any) {
      spinner.fail(`Discovery failed: ${e.message}`);
    }
  });

// ---------------------------------------------------------------------------
// sentinel analyze
// ---------------------------------------------------------------------------

program
  .command('analyze <config>')
  .description('Deep analysis of a specific MCP server config file')
  .option('--verbose', 'Show all details')
  .action(async (configPath, opts) => {
    printBanner();
    const spinner = ora(`Analyzing ${configPath}...`).start();

    try {
      if (!fs.existsSync(configPath)) {
        spinner.fail(`File not found: ${configPath}`);
        return;
      }

      const content = fs.readFileSync(configPath, 'utf-8');
      const config = JSON.parse(content);
      const { GenericParser } = require('@mcp-sentinel/collector');
      const parser = new GenericParser();
      const result = parser.parse(configPath);

      spinner.succeed(`Parsed ${result.servers.length} server(s)`);

      const scanner = new ScannerEngine();

      for (const server of result.servers) {
        console.log(chalk.bold.cyan(`\n  🔍 Analyzing: ${server.name}`));
        console.log(chalk.dim(`     Command: ${server.command} ${(server.args || []).join(' ')}`));
        console.log(chalk.dim(`     Transport: ${server.transport}`));
        console.log(chalk.dim(`     Auth: ${server.metadata?.authPosture}`));

        const ctx: DetectorContext = { server, configContent: content };
        const findings = scanner.scan(ctx);

        if (findings.length === 0) {
          console.log(chalk.green('     ✅ No findings detected'));
        } else {
          console.log(chalk.yellow(`     ⚠ ${findings.length} finding(s) detected:\n`));
          for (const f of findings) {
            console.log(`     ${colorSeverity(f.severity)} ${f.title}`);
            console.log(chalk.dim(`       ${f.description}`));
            console.log(chalk.dim(`       Remediation: ${f.remediation}`));
            console.log('');
          }
        }
      }
    } catch (e: any) {
      spinner.fail(`Analysis failed: ${e.message}`);
    }
  });

// ---------------------------------------------------------------------------
// sentinel detonate
// ---------------------------------------------------------------------------

program
  .command('detonate <config>')
  .description('Runtime detonation of an MCP server in a sandbox')
  .option('--timeout <ms>', 'Timeout in milliseconds', '30000')
  .option('--no-honeytokens', 'Disable honeytoken seeding')
  .option('--no-fuzzing', 'Disable protocol fuzzing')
  .action(async (configPath, opts) => {
    printBanner();
    const spinner = ora('Preparing detonation sandbox...').start();

    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      const { GenericParser } = require('@mcp-sentinel/collector');
      const parser = new GenericParser();
      const result = parser.parse(configPath);

      if (result.servers.length === 0) {
        spinner.fail('No servers found in config');
        return;
      }

      const scheduler = new DetonationScheduler();

      for (const server of result.servers) {
        spinner.text = `Detonating: ${server.name}...`;

        const jobId = scheduler.enqueue({
          serverId: server.id,
          serverConfig: server,
          options: {
            timeout: parseInt(opts.timeout),
            enableHoneytokens: opts.honeytokens !== false,
            enableNetworkCapture: true,
            enableFileTracing: true,
            enableEnvTracing: true,
            enableFuzzing: opts.fuzzing !== false,
            syntheticWorkspace: true,
            allowedDomains: [],
            probeTypes: ['traversal', 'injection', 'fuzz'],
          },
        });

        const detonationResult = await scheduler.processNext();

        if (detonationResult) {
          spinner.succeed(`Detonation complete for: ${server.name}`);

          console.log(chalk.bold.cyan(`\n  💥 Detonation Results: ${server.name}`));
          console.log(chalk.dim(`     Duration: ${detonationResult.duration}ms`));
          console.log(chalk.dim(`     Status: ${detonationResult.status}`));
          console.log(chalk.dim(`     Processes: ${detonationResult.trace.processTree.length}`));
          console.log(chalk.dim(`     File accesses: ${detonationResult.trace.fileAccess.length}`));
          console.log(chalk.dim(`     Network events: ${detonationResult.trace.networkEvents.length}`));
          console.log(chalk.dim(`     Env accesses: ${detonationResult.trace.envAccess.length}`));
          console.log(chalk.dim(`     Honeytoken hits: ${detonationResult.trace.honeytokenHits.length}`));
          console.log(chalk.dim(`     Probe results: ${detonationResult.trace.probeResults.length}`));

          if (detonationResult.trace.honeytokenHits.length > 0) {
            console.log(chalk.red.bold('\n     🚨 HONEYTOKEN HITS DETECTED!'));
            for (const hit of detonationResult.trace.honeytokenHits) {
              console.log(chalk.red(`       Type: ${hit.tokenType}, Accessed: ${hit.accessedAt}`));
            }
          }

          console.log(chalk.dim(`\n     Evidence bundle: ${detonationResult.evidenceBundle.id}`));
          if (detonationResult.evidenceBundle.attestation) {
            console.log(chalk.dim(`     Attestation: SHA-256 signed at ${detonationResult.evidenceBundle.attestation.timestamp}`));
          }
        } else {
          spinner.warn(`Detonation incomplete for: ${server.name}`);
        }
      }
    } catch (e: any) {
      spinner.fail(`Detonation failed: ${e.message}`);
    }
  });

// ---------------------------------------------------------------------------
// sentinel policy
// ---------------------------------------------------------------------------

program
  .command('policy')
  .description('Evaluate servers against security policies')
  .option('-b, --bundle <name>', 'Policy bundle: strict, standard, permissive', 'standard')
  .option('--dry-run', 'Evaluate without enforcement')
  .option('--list', 'List available policy bundles and rules')
  .action(async (opts) => {
    printBanner();

    if (opts.list) {
      const bundles = getAllPolicyBundles();
      for (const bundle of bundles) {
        console.log(chalk.bold.cyan(`\n  📜 ${bundle.name} (${bundle.bundle})`));
        console.log(chalk.dim(`     ${bundle.description}`));
        const table = new Table({
          head: ['Rule', 'Action', 'Severity', 'Description'],
          style: { head: ['cyan'] },
        });
        for (const rule of bundle.rules) {
          table.push([
            rule.name,
            rule.action === 'deny' ? chalk.red(rule.action) : chalk.yellow(rule.action),
            colorSeverity(rule.severity),
            rule.description,
          ]);
        }
        console.log(table.toString());
      }
      return;
    }

    const spinner = ora('Evaluating policies...').start();
    try {
      const db = new SentinelDB();
      const servers = db.getAllServers();
      const bundles = getAllPolicyBundles();
      const selectedBundle = bundles.find(b => b.bundle === opts.bundle) || bundles[1];

      const engine = new PolicyEngine(opts.dryRun);
      engine.loadPolicies([selectedBundle]);

      let totalDecisions = 0;
      for (const server of servers) {
        const findings = db.getFindingsForServer(server.id);
        const decisions = engine.evaluate(server, findings);
        totalDecisions += decisions.length;

        for (const d of decisions) {
          const icon = d.verdict === 'deny' ? '🚫' : d.verdict === 'review' ? '👀' : '✅';
          console.log(`  ${icon} ${d.verdict.toUpperCase()} — ${d.reason}`);
        }
      }

      const verdicts = engine.getVerdictSummary(engine.getDecisions());
      spinner.succeed(`Policy evaluation complete (${totalDecisions} decisions)`);
      console.log(chalk.green(`  ✅ Allowed: ${verdicts.allowed}`));
      console.log(chalk.red(`  🚫 Denied: ${verdicts.denied}`));
      console.log(chalk.yellow(`  👀 Review: ${verdicts.review}`));
      console.log(chalk.dim(`  📋 Waived: ${verdicts.waived}`));
      if (opts.dryRun) console.log(chalk.dim('  (dry-run mode — no enforcement)'));

      db.close();
    } catch (e: any) {
      spinner.fail(`Policy evaluation failed: ${e.message}`);
    }
  });

// ---------------------------------------------------------------------------
// sentinel evidence
// ---------------------------------------------------------------------------

program
  .command('evidence')
  .description('List, show, or export evidence bundles')
  .option('-l, --list', 'List recent scan results')
  .option('-s, --show <id>', 'Show details of a specific scan')
  .option('-e, --export <format>', 'Export: json, csv, sarif')
  .action(async (opts) => {
    printBanner();
    try {
      const db = new SentinelDB();

      if (opts.list || (!opts.show && !opts.export)) {
        const scans = db.getScanHistory(20);
        if (scans.length === 0) {
          console.log(chalk.yellow('\n  No scan results found. Run `sentinel scan` first.\n'));
          db.close();
          return;
        }

        const table = new Table({
          head: ['ID', 'Date', 'Servers', 'Findings', 'Risk Score'],
          style: { head: ['cyan'] },
        });

        for (const scan of scans) {
          table.push([
            scan.id.slice(0, 8),
            scan.completedAt,
            scan.serversScanned.toString(),
            scan.summary?.totalFindings?.toString() || '0',
            scan.riskScore?.toFixed(1) || '-',
          ]);
        }

        console.log(chalk.bold.cyan('\n  📦 Evidence — Scan History\n'));
        console.log(table.toString());
      }

      if (opts.show) {
        const findings = db.getAllFindings();
        console.log(chalk.bold.cyan(`\n  📦 Evidence Details\n`));
        console.log(`  Total findings: ${findings.length}`);
        for (const f of findings.slice(0, 20)) {
          console.log(`  ${colorSeverity(f.severity)} ${f.title} — ${f.description.slice(0, 80)}`);
        }
      }

      const log = db.getAuditLog(10);
      if (log.length > 0) {
        console.log(chalk.bold.cyan('\n  📋 Recent Audit Log\n'));
        for (const entry of log) {
          console.log(chalk.dim(`  [${entry.timestamp}] ${entry.action} ${entry.entityType}:${entry.entityId.slice(0, 8)} by ${entry.actor}`));
        }
      }

      db.close();
    } catch (e: any) {
      console.error(chalk.red(`Evidence error: ${e.message}`));
    }
  });

// ---------------------------------------------------------------------------
// sentinel registry
// ---------------------------------------------------------------------------

program
  .command('registry')
  .description('Sync with MCP registry')
  .option('--sync', 'Sync server entries from the public MCP registry')
  .action(async (opts) => {
    printBanner();
    console.log(chalk.cyan('\n  📡 MCP Registry Integration\n'));
    console.log(chalk.dim('  The official MCP Registry provides a system of truth for public MCP servers.'));
    console.log(chalk.dim('  Registry URL: https://registry.modelcontextprotocol.io'));
    console.log('');

    if (opts.sync) {
      const spinner = ora('Syncing with MCP registry...').start();
      // Placeholder for actual registry API integration
      spinner.succeed('Registry sync complete (feature in development)');
      console.log(chalk.dim('  Registry sync will be available when the official registry API is publicly accessible.'));
    } else {
      console.log(chalk.dim('  Use --sync to synchronize with the public MCP registry'));
    }
  });

// ---------------------------------------------------------------------------
// sentinel report
// ---------------------------------------------------------------------------

program
  .command('report')
  .description('Generate a comprehensive posture report')
  .option('-f, --format <format>', 'Format: text, json, sarif', 'text')
  .option('-o, --output <file>', 'Output file')
  .action(async (opts) => {
    printBanner();
    const spinner = ora('Generating posture report...').start();

    try {
      const db = new SentinelDB();
      const stats = db.getStats();
      const findings = db.getAllFindings();
      const servers = db.getAllServers();
      const scans = db.getScanHistory(5);

      spinner.succeed('Report generated');

      console.log(chalk.bold.cyan('\n  ════════════════════════════════════════════'));
      console.log(chalk.bold.cyan('   MCP SENTINEL — POSTURE REPORT'));
      console.log(chalk.bold.cyan('  ════════════════════════════════════════════\n'));

      console.log(chalk.bold('  Overview'));
      console.log(`    Total Servers:    ${stats.totalServers}`);
      console.log(`    Total Findings:   ${stats.totalFindings}`);
      console.log(`    Open Findings:    ${chalk.yellow(stats.openFindings.toString())}`);
      console.log(`    Critical:         ${chalk.red(stats.criticalFindings.toString())}`);
      console.log(`    High:             ${chalk.red(stats.highFindings.toString())}`);
      console.log(`    Avg Risk Score:   ${stats.avgRiskScore.toFixed(1)}/10`);
      console.log(`    Total Scans:      ${stats.totalScans}`);
      console.log(`    Active Waivers:   ${stats.totalWaivers}`);

      if (servers.length > 0) {
        console.log(chalk.bold('\n  Server Inventory'));
        const table = new Table({
          head: ['Name', 'Transport', 'Risk', 'Status', 'Findings'],
          style: { head: ['cyan'] },
        });
        for (const s of servers) {
          const serverFindings = findings.filter(f => f.serverId === s.id);
          table.push([
            s.name,
            s.transport,
            s.riskScore?.toFixed(1) || '-',
            s.approvalStatus,
            serverFindings.length.toString(),
          ]);
        }
        console.log(table.toString());
      }

      console.log('');
      db.close();
    } catch (e: any) {
      spinner.fail(`Report generation failed: ${e.message}`);
    }
  });

// ---------------------------------------------------------------------------
// Parse and execute
// ---------------------------------------------------------------------------

program.parse();
