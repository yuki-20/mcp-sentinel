// ============================================================================
// Collector Service — Config Parsers for MCP Clients
// Parses Claude Desktop, Cursor, VS Code, and Claude Code configs
// ============================================================================

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
  Server, Client, ClientType, TransportType, AuthPosture,
  createId, createTimestamp,
} from '@mcp-sentinel/core';

// ---------------------------------------------------------------------------
// Parser result type
// ---------------------------------------------------------------------------

export interface ParseResult {
  client: Client;
  servers: Server[];
  errors: string[];
}

// ---------------------------------------------------------------------------
// Base parser with shared utilities
// ---------------------------------------------------------------------------

abstract class ConfigParser {
  abstract clientType: ClientType;
  abstract clientName: string;
  abstract getConfigPaths(): string[];

  parse(configPath?: string): ParseResult {
    const paths = configPath ? [configPath] : this.getConfigPaths();
    const errors: string[] = [];
    let content: any = null;
    let resolvedPath = '';

    for (const p of paths) {
      try {
        if (fs.existsSync(p)) {
          const raw = fs.readFileSync(p, 'utf-8');
          content = JSON.parse(raw);
          resolvedPath = p;
          break;
        }
      } catch (e: any) {
        errors.push(`Failed to parse ${p}: ${e.message}`);
      }
    }

    if (!content) {
      return {
        client: this.createClient('', 'not found'),
        servers: [],
        errors: configPath
          ? [`Config file not found: ${configPath}`]
          : [`No config found for ${this.clientName}`],
      };
    }

    const client = this.createClient(resolvedPath);
    const servers = this.extractServers(content, client.id, resolvedPath);

    return { client, servers, errors };
  }

  protected createClient(configPath: string, version: string = 'unknown'): Client {
    return {
      id: createId(),
      hostId: os.hostname(),
      type: this.clientType,
      name: this.clientName,
      version,
      configPath,
      discoveredAt: createTimestamp(),
      lastSeenAt: createTimestamp(),
    };
  }

  protected abstract extractServers(config: any, clientId: string, configPath: string): Server[];

  protected inferTransport(serverConfig: any): TransportType {
    if (serverConfig.url) {
      if (serverConfig.url.startsWith('http')) return TransportType.HTTP;
      if (serverConfig.url.includes('sse')) return TransportType.SSE;
      return TransportType.STREAMABLE_HTTP;
    }
    if (serverConfig.command) return TransportType.STDIO;
    return TransportType.UNKNOWN;
  }

  protected inferAuthPosture(serverConfig: any): AuthPosture {
    const env = serverConfig.env || {};
    const envKeys = Object.keys(env).map(k => k.toLowerCase());

    // Check for OAuth indicators
    if (envKeys.some(k => k.includes('oauth') || k.includes('client_id') || k.includes('client_secret'))) {
      return AuthPosture.OAUTH;
    }
    // Check for API key
    if (envKeys.some(k => k.includes('api_key') || k.includes('apikey') || k.includes('api-key'))) {
      return AuthPosture.API_KEY;
    }
    // Check for bearer/token
    if (envKeys.some(k => k.includes('token') || k.includes('bearer') || k.includes('auth'))) {
      return AuthPosture.BEARER_TOKEN;
    }

    return serverConfig.command ? AuthPosture.NONE : AuthPosture.UNKNOWN;
  }
}

// ---------------------------------------------------------------------------
// Claude Desktop Config Parser
// ---------------------------------------------------------------------------

export class ClaudeDesktopParser extends ConfigParser {
  clientType = ClientType.CLAUDE_DESKTOP;
  clientName = 'Claude Desktop';

  getConfigPaths(): string[] {
    const home = os.homedir();
    const platform = os.platform();

    if (platform === 'darwin') {
      return [
        path.join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
      ];
    } else if (platform === 'win32') {
      return [
        path.join(process.env.APPDATA || '', 'Claude', 'claude_desktop_config.json'),
      ];
    } else {
      return [
        path.join(home, '.config', 'claude', 'claude_desktop_config.json'),
      ];
    }
  }

  protected extractServers(config: any, clientId: string, configPath: string): Server[] {
    const servers: Server[] = [];
    const mcpServers = config.mcpServers || {};

    for (const [name, cfg] of Object.entries(mcpServers)) {
      const serverConfig = cfg as any;
      servers.push({
        id: createId(),
        name,
        command: serverConfig.command || '',
        args: serverConfig.args || [],
        env: serverConfig.env || {},
        transport: this.inferTransport(serverConfig),
        url: serverConfig.url,
        clientId,
        discoveredAt: createTimestamp(),
        approvalStatus: 'pending' as any,
        riskScore: undefined,
        metadata: {
          configPath,
          authPosture: this.inferAuthPosture(serverConfig),
          rawConfig: serverConfig,
        },
      });
    }

    return servers;
  }
}

// ---------------------------------------------------------------------------
// Cursor Config Parser
// ---------------------------------------------------------------------------

export class CursorParser extends ConfigParser {
  clientType = ClientType.CURSOR;
  clientName = 'Cursor';

  getConfigPaths(): string[] {
    const home = os.homedir();
    const platform = os.platform();

    // Cursor stores MCP config in workspace or user settings
    const paths = [
      path.join(home, '.cursor', 'mcp.json'),
      path.join(process.cwd(), '.cursor', 'mcp.json'),
    ];

    if (platform === 'darwin') {
      paths.push(path.join(home, 'Library', 'Application Support', 'Cursor', 'User', 'globalStorage', 'cursor.mcp', 'mcp.json'));
    } else if (platform === 'win32') {
      paths.push(path.join(process.env.APPDATA || '', 'Cursor', 'User', 'globalStorage', 'cursor.mcp', 'mcp.json'));
    }

    return paths;
  }

  protected extractServers(config: any, clientId: string, configPath: string): Server[] {
    const servers: Server[] = [];
    const mcpServers = config.mcpServers || config.servers || {};

    for (const [name, cfg] of Object.entries(mcpServers)) {
      const serverConfig = cfg as any;
      servers.push({
        id: createId(),
        name,
        command: serverConfig.command || '',
        args: serverConfig.args || [],
        env: serverConfig.env || {},
        transport: this.inferTransport(serverConfig),
        url: serverConfig.url,
        clientId,
        discoveredAt: createTimestamp(),
        approvalStatus: 'pending' as any,
        riskScore: undefined,
        metadata: {
          configPath,
          authPosture: this.inferAuthPosture(serverConfig),
          disabled: serverConfig.disabled || false,
          rawConfig: serverConfig,
        },
      });
    }

    return servers;
  }
}

// ---------------------------------------------------------------------------
// VS Code MCP Settings Parser
// ---------------------------------------------------------------------------

export class VSCodeParser extends ConfigParser {
  clientType = ClientType.VSCODE;
  clientName = 'VS Code';

  getConfigPaths(): string[] {
    const home = os.homedir();
    const platform = os.platform();

    const paths = [
      path.join(process.cwd(), '.vscode', 'mcp.json'),
      path.join(process.cwd(), '.vscode', 'settings.json'),
    ];

    if (platform === 'darwin') {
      paths.push(path.join(home, 'Library', 'Application Support', 'Code', 'User', 'settings.json'));
    } else if (platform === 'win32') {
      paths.push(path.join(process.env.APPDATA || '', 'Code', 'User', 'settings.json'));
    } else {
      paths.push(path.join(home, '.config', 'Code', 'User', 'settings.json'));
    }

    return paths;
  }

  protected extractServers(config: any, clientId: string, configPath: string): Server[] {
    const servers: Server[] = [];

    // VS Code can have MCP config in a dedicated mcp.json or in settings.json
    let mcpConfig: any = {};
    if (config.servers) {
      mcpConfig = config.servers;
    } else if (config['mcp.servers']) {
      mcpConfig = config['mcp.servers'];
    } else if (config.mcp && config.mcp.servers) {
      mcpConfig = config.mcp.servers;
    }

    for (const [name, cfg] of Object.entries(mcpConfig)) {
      const serverConfig = cfg as any;
      servers.push({
        id: createId(),
        name,
        command: serverConfig.command || '',
        args: serverConfig.args || [],
        env: serverConfig.env || {},
        transport: this.inferTransport(serverConfig),
        url: serverConfig.url,
        clientId,
        discoveredAt: createTimestamp(),
        approvalStatus: 'pending' as any,
        riskScore: undefined,
        metadata: {
          configPath,
          authPosture: this.inferAuthPosture(serverConfig),
          rawConfig: serverConfig,
        },
      });
    }

    return servers;
  }
}

// ---------------------------------------------------------------------------
// Claude Code Config Parser
// ---------------------------------------------------------------------------

export class ClaudeCodeParser extends ConfigParser {
  clientType = ClientType.CLAUDE_CODE;
  clientName = 'Claude Code';

  getConfigPaths(): string[] {
    const home = os.homedir();
    return [
      path.join(home, '.claude', 'mcp_servers.json'),
      path.join(process.cwd(), '.claude', 'mcp_servers.json'),
      path.join(home, '.claude.json'),
    ];
  }

  protected extractServers(config: any, clientId: string, configPath: string): Server[] {
    const servers: Server[] = [];

    // Claude Code can have servers at root level or nested
    const mcpServers = config.mcpServers || config.servers || config;

    if (typeof mcpServers !== 'object') return servers;

    for (const [name, cfg] of Object.entries(mcpServers)) {
      const serverConfig = cfg as any;
      if (typeof serverConfig !== 'object') continue;

      servers.push({
        id: createId(),
        name,
        command: serverConfig.command || '',
        args: serverConfig.args || [],
        env: serverConfig.env || {},
        transport: this.inferTransport(serverConfig),
        url: serverConfig.url,
        clientId,
        discoveredAt: createTimestamp(),
        approvalStatus: 'pending' as any,
        riskScore: undefined,
        metadata: {
          configPath,
          authPosture: this.inferAuthPosture(serverConfig),
          rawConfig: serverConfig,
        },
      });
    }

    return servers;
  }
}

// ---------------------------------------------------------------------------
// Generic Config Parser — parses any JSON with MCP server definitions
// ---------------------------------------------------------------------------

export class GenericParser extends ConfigParser {
  clientType = ClientType.CUSTOM;
  clientName = 'Custom';

  getConfigPaths(): string[] {
    return [];
  }

  protected extractServers(config: any, clientId: string, configPath: string): Server[] {
    const servers: Server[] = [];

    // Try common structures
    const candidates = [
      config.mcpServers,
      config.servers,
      config.mcp?.servers,
      config,
    ];

    for (const candidate of candidates) {
      if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
        for (const [name, cfg] of Object.entries(candidate)) {
          const serverConfig = cfg as any;
          if (typeof serverConfig === 'object' && (serverConfig.command || serverConfig.url)) {
            servers.push({
              id: createId(),
              name,
              command: serverConfig.command || '',
              args: serverConfig.args || [],
              env: serverConfig.env || {},
              transport: this.inferTransport(serverConfig),
              url: serverConfig.url,
              clientId,
              discoveredAt: createTimestamp(),
              approvalStatus: 'pending' as any,
              riskScore: undefined,
              metadata: {
                configPath,
                authPosture: this.inferAuthPosture(serverConfig),
                rawConfig: serverConfig,
              },
            });
          }
        }
        if (servers.length > 0) break; // Found servers, stop trying
      }
    }

    return servers;
  }
}

// ---------------------------------------------------------------------------
// Discovery orchestrator — runs all parsers
// ---------------------------------------------------------------------------

export function discoverAllClients(customPaths?: string[]): ParseResult[] {
  const parsers: ConfigParser[] = [
    new ClaudeDesktopParser(),
    new CursorParser(),
    new VSCodeParser(),
    new ClaudeCodeParser(),
  ];

  const results: ParseResult[] = [];

  // Run all known client parsers
  for (const parser of parsers) {
    const result = parser.parse();
    if (result.servers.length > 0) {
      results.push(result);
    }
  }

  // Parse custom paths
  if (customPaths) {
    const generic = new GenericParser();
    for (const p of customPaths) {
      const result = generic.parse(p);
      if (result.servers.length > 0) {
        results.push(result);
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// File watcher for continuous monitoring
// ---------------------------------------------------------------------------

export interface WatcherOptions {
  onServerDiscovered: (server: Server, client: Client) => void;
  onServerRemoved: (serverId: string) => void;
  onError: (error: Error) => void;
}

export class ConfigWatcher {
  private watchers: fs.FSWatcher[] = [];
  private knownServers: Map<string, Server> = new Map();
  private options: WatcherOptions;

  constructor(options: WatcherOptions) {
    this.options = options;
  }

  start(): void {
    const parsers: ConfigParser[] = [
      new ClaudeDesktopParser(),
      new CursorParser(),
      new VSCodeParser(),
      new ClaudeCodeParser(),
    ];

    for (const parser of parsers) {
      for (const configPath of parser.getConfigPaths()) {
        try {
          if (fs.existsSync(configPath)) {
            const watcher = fs.watch(configPath, () => {
              this.handleConfigChange(parser);
            });
            this.watchers.push(watcher);
          }
        } catch (_e) {
          // Path doesn't exist yet, skip
        }
      }
    }
  }

  private handleConfigChange(parser: ConfigParser): void {
    try {
      const result = parser.parse();
      const currentNames = new Set(result.servers.map(s => s.name));

      // Check for new or changed servers
      for (const server of result.servers) {
        const key = `${parser.clientType}:${server.name}`;
        if (!this.knownServers.has(key)) {
          this.knownServers.set(key, server);
          this.options.onServerDiscovered(server, result.client);
        }
      }

      // Check for removed servers
      for (const [key, server] of this.knownServers) {
        if (key.startsWith(`${parser.clientType}:`) && !currentNames.has(server.name)) {
          this.knownServers.delete(key);
          this.options.onServerRemoved(server.id);
        }
      }
    } catch (e: any) {
      this.options.onError(e);
    }
  }

  stop(): void {
    for (const watcher of this.watchers) {
      watcher.close();
    }
    this.watchers = [];
  }
}
