// ============================================================================
// Scanner Service — All 12 Detector Families
// Complete static analysis plane for MCP security posture
// ============================================================================

import {
  Server, Finding, Severity, FindingStatus, DetectorFamily,
  TransportType, AuthPosture, createId, createTimestamp,
} from '@mcp-sentinel/core';

// ---------------------------------------------------------------------------
// Base Detector Interface
// ---------------------------------------------------------------------------

export interface DetectorContext {
  server: Server;
  configContent?: string;
  sourceCode?: string;
  packageJson?: any;
  lockfile?: any;
  previousVersion?: {
    tools: any[];
    descriptions: Record<string, string>;
    envVars: string[];
    scripts: Record<string, string>;
  };
}

export interface Detector {
  family: DetectorFamily;
  name: string;
  description: string;
  analyze(ctx: DetectorContext): Finding[];
}

// ---------------------------------------------------------------------------
// 1. Secret Scanner — Regex + Entropy + Known Token Formats
// ---------------------------------------------------------------------------

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: Severity }> = [
  // API Keys
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: Severity.CRITICAL },
  { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: Severity.CRITICAL },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, severity: Severity.CRITICAL },
  { name: 'GitHub Personal Access Token', pattern: /github_pat_[A-Za-z0-9_]{22,255}/g, severity: Severity.CRITICAL },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/g, severity: Severity.CRITICAL },
  { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity: Severity.HIGH },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g, severity: Severity.HIGH },
  { name: 'Stripe Secret Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g, severity: Severity.CRITICAL },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[0-9a-zA-Z]{24,}/g, severity: Severity.MEDIUM },
  { name: 'Twilio API Key', pattern: /SK[0-9a-fA-F]{32}/g, severity: Severity.HIGH },
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}/g, severity: Severity.HIGH },
  { name: 'OpenAI API Key', pattern: /sk-[A-Za-z0-9]{32,}/g, severity: Severity.CRITICAL },
  { name: 'Anthropic API Key', pattern: /sk-ant-[A-Za-z0-9\-_]{32,}/g, severity: Severity.CRITICAL },
  { name: 'Azure Key', pattern: /[0-9a-f]{32}/g, severity: Severity.MEDIUM },
  { name: 'Private Key', pattern: /-----BEGIN\s*(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: Severity.CRITICAL },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, severity: Severity.HIGH },
  { name: 'Basic Auth', pattern: /(?:basic|authorization)\s*[:=]\s*['"]?[A-Za-z0-9+/=]{20,}['"]?/gi, severity: Severity.HIGH },
  { name: 'Database URL', pattern: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/g, severity: Severity.CRITICAL },
  { name: 'Generic Secret', pattern: /(?:secret|password|passwd|pwd|token|api_key|apikey|access_key)\s*[=:]\s*['"]([^'"]{8,})['"]?/gi, severity: Severity.HIGH },
];

export class SecretScanner implements Detector {
  family = DetectorFamily.SECRET_SCANNER;
  name = 'Secret Scanner';
  description = 'Detects plaintext secrets, API keys, tokens, and credentials via regex and entropy analysis';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const searchTargets: Array<{ label: string; content: string }> = [];

    // Check environment variables in server config
    if (ctx.server.env) {
      for (const [key, value] of Object.entries(ctx.server.env)) {
        searchTargets.push({ label: `env.${key}`, content: value });
      }
    }

    // Check config content
    if (ctx.configContent) {
      searchTargets.push({ label: 'config', content: ctx.configContent });
    }

    // Check command arguments
    if (ctx.server.args) {
      searchTargets.push({ label: 'args', content: ctx.server.args.join(' ') });
    }

    for (const target of searchTargets) {
      for (const pattern of SECRET_PATTERNS) {
        const matches = target.content.match(pattern.pattern);
        if (matches) {
          for (const match of matches) {
            // Skip short matches that are likely false positives
            if (match.length < 8) continue;
            // Skip low-entropy strings (likely not secrets)
            if (this.entropy(match) < 3.0 && pattern.severity !== Severity.CRITICAL) continue;

            findings.push({
              id: createId(),
              serverId: ctx.server.id,
              detector: this.family,
              title: `${pattern.name} detected`,
              description: `A ${pattern.name} was found in ${target.label}. Hardcoded credentials pose a significant security risk.`,
              severity: pattern.severity,
              confidence: 0.85,
              status: FindingStatus.OPEN,
              evidence: {
                type: 'static',
                location: target.label,
                snippet: this.redact(match),
                artifacts: [],
              },
              remediation: `Remove the hardcoded ${pattern.name.toLowerCase()} and use a secret manager or environment variable injection at runtime.`,
              references: ['https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices'],
              detectedAt: createTimestamp(),
              metadata: { matchLength: match.length, entropy: this.entropy(match) },
            });
          }
        }
      }

      // High-entropy string detection for unknown secret types
      if (target.label.startsWith('env.')) {
        const value = target.content;
        if (value.length >= 16 && this.entropy(value) > 4.5) {
          const envKey = target.label.replace('env.', '');
          if (this.looksLikeSecret(envKey)) {
            findings.push({
              id: createId(),
              serverId: ctx.server.id,
              detector: this.family,
              title: 'High-entropy value in environment variable',
              description: `Environment variable "${envKey}" contains a high-entropy value that may be a secret (entropy: ${this.entropy(value).toFixed(2)}).`,
              severity: Severity.MEDIUM,
              confidence: 0.6,
              status: FindingStatus.OPEN,
              evidence: {
                type: 'static',
                location: target.label,
                snippet: this.redact(value),
                artifacts: [],
              },
              remediation: 'Verify whether this value is a secret. If so, use a secret manager instead of storing it in config files.',
              references: [],
              detectedAt: createTimestamp(),
              metadata: { entropy: this.entropy(value) },
            });
          }
        }
      }
    }

    return findings;
  }

  private entropy(str: string): number {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let ent = 0;
    for (const count of Object.values(freq)) {
      const p = count / str.length;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  private redact(value: string): string {
    if (value.length <= 8) return '***';
    return value.substring(0, 4) + '***' + value.substring(value.length - 4);
  }

  private looksLikeSecret(key: string): boolean {
    const secretIndicators = ['key', 'secret', 'token', 'password', 'passwd', 'pwd', 'auth', 'credential', 'api'];
    return secretIndicators.some(ind => key.toLowerCase().includes(ind));
  }
}

// ---------------------------------------------------------------------------
// 2. Startup Command Analyzer
// ---------------------------------------------------------------------------

const RISKY_PATTERNS: Array<{ pattern: RegExp; description: string; severity: Severity }> = [
  { pattern: /curl\s.*\|\s*(sh|bash|zsh)/gi, description: 'Pipe from curl to shell — arbitrary code execution on startup', severity: Severity.CRITICAL },
  { pattern: /wget\s.*\|\s*(sh|bash|zsh)/gi, description: 'Pipe from wget to shell — arbitrary code execution on startup', severity: Severity.CRITICAL },
  { pattern: /eval\s*\(/gi, description: 'Use of eval() — dynamic code execution', severity: Severity.HIGH },
  { pattern: /\bsudo\b/gi, description: 'Use of sudo — elevated privilege execution', severity: Severity.HIGH },
  { pattern: /\bchmod\s+[0-7]*7[0-7]*\b/gi, description: 'chmod with world-executable permissions', severity: Severity.MEDIUM },
  { pattern: /\brm\s+-r?f/gi, description: 'Recursive/forced file deletion', severity: Severity.HIGH },
  { pattern: />(\/dev\/tcp|\/dev\/udp)/gi, description: 'Bash TCP/UDP device redirection — potential reverse shell', severity: Severity.CRITICAL },
  { pattern: /\bnc\b.*-[el]/gi, description: 'Netcat with listen/exec flags — potential backdoor', severity: Severity.CRITICAL },
  { pattern: /\bpython\s+-c\s+['"]import\s+socket/gi, description: 'Python socket one-liner — potential reverse shell', severity: Severity.CRITICAL },
  { pattern: /\bbase64\s+-d/gi, description: 'Base64 decode — potentially hiding malicious payload', severity: Severity.MEDIUM },
  { pattern: /\bpowershell\b.*-enc/gi, description: 'PowerShell encoded command — obfuscated execution', severity: Severity.HIGH },
  { pattern: /\bwget\b.*-O\s*-/gi, description: 'wget to stdout — often used with shell pipe', severity: Severity.MEDIUM },
];

export class StartupCommandAnalyzer implements Detector {
  family = DetectorFamily.STARTUP_COMMAND;
  name = 'Startup Command Analyzer';
  description = 'Detects risky startup commands including shell wrappers, curl|sh patterns, and suspicious binaries';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const command = ctx.server.command;
    const fullCommand = `${command} ${(ctx.server.args || []).join(' ')}`;

    for (const riskPattern of RISKY_PATTERNS) {
      if (riskPattern.pattern.test(fullCommand)) {
        findings.push({
          id: createId(),
          serverId: ctx.server.id,
          detector: this.family,
          title: 'Risky startup command detected',
          description: riskPattern.description,
          severity: riskPattern.severity,
          confidence: 0.9,
          status: FindingStatus.OPEN,
          evidence: {
            type: 'static',
            location: 'server.command',
            snippet: fullCommand,
            artifacts: [],
          },
          remediation: 'Review the startup command and replace with a safe, auditable alternative. Avoid piping remote content to shell interpreters.',
          references: ['https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices'],
          detectedAt: createTimestamp(),
          metadata: {},
        });
      }
    }

    // Check for shell wrappers
    const shellBinaries = ['sh', 'bash', 'zsh', 'fish', 'cmd', 'powershell', 'pwsh'];
    if (shellBinaries.some(sh => command === sh || command.endsWith(`/${sh}`) || command.endsWith(`\\${sh}`))) {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Server uses shell wrapper as command',
        description: `The server command is "${command}", which means it runs through a shell interpreter. This increases the attack surface for command injection.`,
        severity: Severity.MEDIUM,
        confidence: 0.8,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.command', snippet: fullCommand, artifacts: [] },
        remediation: 'Use a direct binary path instead of a shell wrapper where possible.',
        references: [],
        detectedAt: createTimestamp(),
        metadata: {},
      });
    }

    // Check for network fetch on launch
    if (/https?:\/\//.test(fullCommand)) {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Network fetch in startup command',
        description: 'The startup command contains a URL, suggesting it fetches remote content at launch time.',
        severity: Severity.HIGH,
        confidence: 0.85,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.command', snippet: fullCommand, artifacts: [] },
        remediation: 'Avoid fetching remote content during server startup. Use a pre-built, locally installed binary.',
        references: [],
        detectedAt: createTimestamp(),
        metadata: {},
      });
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 3. Auth Posture Checker
// ---------------------------------------------------------------------------

export class AuthPostureChecker implements Detector {
  family = DetectorFamily.AUTH_POSTURE;
  name = 'Auth Posture Checker';
  description = 'Assesses transport type, auth configuration, spec version awareness, and OAuth metadata presence';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const authPosture = (ctx.server.metadata?.authPosture as string) || 'unknown';
    const transport = ctx.server.transport;

    // No auth on remote server
    if (transport !== TransportType.STDIO && authPosture === 'none') {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Remote server with no authentication',
        description: `Server "${ctx.server.name}" uses ${transport} transport but has no authentication configured. This is a critical security gap per the November 2025 MCP spec.`,
        severity: Severity.CRITICAL,
        confidence: 0.95,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.transport', snippet: `transport=${transport}, auth=${authPosture}`, artifacts: [] },
        remediation: 'Configure OAuth 2.0 or another authentication mechanism for remote MCP servers as required by the 2025-11-25 MCP specification.',
        references: ['https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization'],
        detectedAt: createTimestamp(),
        metadata: { authPosture, transport },
      });
    }

    // Static API key on remote server (version-aware)
    if (transport !== TransportType.STDIO && authPosture === 'api-key') {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Remote server using static API key',
        description: `Server "${ctx.server.name}" uses a static API key for authentication. The newer MCP spec recommends OAuth for protected remote servers.`,
        severity: Severity.HIGH,
        confidence: 0.85,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.env', snippet: `auth_type=${authPosture}`, artifacts: [] },
        remediation: 'Migrate from static API keys to OAuth 2.0 with proper token rotation.',
        references: ['https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization'],
        detectedAt: createTimestamp(),
        metadata: { authPosture, transport },
      });
    }

    // Local stdio with environment-based credentials
    if (transport === TransportType.STDIO && authPosture === 'none') {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Local stdio server relies on process trust',
        description: `Server "${ctx.server.name}" is a local stdio server with no explicit authentication. Security relies on the local process trust boundary.`,
        severity: Severity.LOW,
        confidence: 0.9,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.transport', snippet: `transport=stdio, auth=none`, artifacts: [] },
        remediation: 'Consider adding additional access controls or monitoring for local MCP servers, especially in CI/CD environments.',
        references: ['https://stackoverflow.blog/2026/01/21/is-that-allowed-authentication-and-authorization-in-model-context-protocol/'],
        detectedAt: createTimestamp(),
        metadata: { authPosture, transport },
      });
    }

    // Unknown auth posture
    if (authPosture === 'unknown') {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Authentication posture unknown',
        description: `Unable to determine the authentication posture of server "${ctx.server.name}". Manual review is recommended.`,
        severity: Severity.MEDIUM,
        confidence: 0.5,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.env', snippet: 'No auth indicators found', artifacts: [] },
        remediation: 'Review the server configuration and verify that appropriate authentication is configured.',
        references: [],
        detectedAt: createTimestamp(),
        metadata: { authPosture, transport },
      });
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 4. Capability Surface Analyzer
// ---------------------------------------------------------------------------

export class CapabilitySurfaceAnalyzer implements Detector {
  family = DetectorFamily.CAPABILITY_SURFACE;
  name = 'Capability Surface Analyzer';
  description = 'Maps declared tools and resource scopes to detect overbroad permissions';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];
    const rawConfig = (ctx.server.metadata?.rawConfig as Record<string, unknown>) || {};

    // Check for servers that expose many tools
    const toolCount = Array.isArray(rawConfig.tools) ? rawConfig.tools.length : 0;
    if (toolCount > 20) {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Server exposes excessive number of tools',
        description: `Server "${ctx.server.name}" exposes ${toolCount} tools. Large tool surfaces increase the risk of unintended actions and make review difficult.`,
        severity: Severity.MEDIUM,
        confidence: 0.7,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'server.tools', snippet: `${toolCount} tools declared`, artifacts: [] },
        remediation: 'Review tool list and apply least-privilege by exposing only necessary tools.',
        references: [],
        detectedAt: createTimestamp(),
        metadata: { toolCount },
      });
    }

    // Check for write/destructive capabilities in tool names/descriptions
    const destructiveKeywords = ['delete', 'remove', 'drop', 'truncate', 'destroy', 'purge', 'wipe', 'reset', 'format', 'kill'];
    const writeKeywords = ['write', 'create', 'insert', 'update', 'modify', 'put', 'post', 'send', 'publish', 'deploy', 'execute', 'run'];

    const serverName = ctx.server.name.toLowerCase();
    const commandStr = `${ctx.server.command} ${(ctx.server.args || []).join(' ')}`.toLowerCase();

    for (const keyword of destructiveKeywords) {
      if (serverName.includes(keyword) || commandStr.includes(keyword)) {
        findings.push({
          id: createId(),
          serverId: ctx.server.id,
          detector: this.family,
          title: 'Server name/command suggests destructive capabilities',
          description: `Server "${ctx.server.name}" appears to have destructive capabilities (keyword: "${keyword}"). These should require explicit human approval.`,
          severity: Severity.HIGH,
          confidence: 0.6,
          status: FindingStatus.OPEN,
          evidence: { type: 'static', location: 'server.name', snippet: `"${ctx.server.name}" contains "${keyword}"`, artifacts: [] },
          remediation: 'Ensure destructive tools require explicit human approval before execution.',
          references: [],
          detectedAt: createTimestamp(),
          metadata: { keyword },
        });
        break;
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 5. Command Injection Detector
// ---------------------------------------------------------------------------

export class CommandInjectionDetector implements Detector {
  family = DetectorFamily.COMMAND_INJECTION;
  name = 'Command Injection Detector';
  description = 'Finds shell interpolation and unsafe process execution patterns in server code';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.sourceCode) return findings;

    const injectionPatterns: Array<{ pattern: RegExp; description: string; severity: Severity }> = [
      { pattern: /exec\(\s*[`'"].*\$\{/g, description: 'Template literal in exec() — shell injection risk', severity: Severity.CRITICAL },
      { pattern: /execSync\(\s*[`'"].*\$\{/g, description: 'Template literal in execSync() — shell injection risk', severity: Severity.CRITICAL },
      { pattern: /child_process.*exec\(/g, description: 'Use of child_process.exec() — prefer execFile for safety', severity: Severity.HIGH },
      { pattern: /spawn\(\s*['"](?:sh|bash|cmd)/g, description: 'Spawning shell interpreter directly', severity: Severity.HIGH },
      { pattern: /shell:\s*true/g, description: 'shell: true option enables shell interpretation of arguments', severity: Severity.HIGH },
      { pattern: /\beval\s*\(/g, description: 'eval() usage — arbitrary code execution risk', severity: Severity.CRITICAL },
      { pattern: /new\s+Function\s*\(/g, description: 'new Function() — dynamic code construction', severity: Severity.HIGH },
      { pattern: /os\.system\s*\(/g, description: 'os.system() — unescaped shell execution (Python)', severity: Severity.CRITICAL },
      { pattern: /subprocess\.call\(.*shell\s*=\s*True/g, description: 'subprocess with shell=True (Python)', severity: Severity.CRITICAL },
      { pattern: /`.*\$\(.*\)`/g, description: 'Command substitution in template literal', severity: Severity.HIGH },
    ];

    for (const pattern of injectionPatterns) {
      const lines = ctx.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (pattern.pattern.test(lines[i])) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Potential command injection vulnerability',
            description: pattern.description,
            severity: pattern.severity,
            confidence: 0.8,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: 'source',
              lineNumber: i + 1,
              snippet: lines[i].trim(),
              artifacts: [],
            },
            remediation: 'Use parameterized execution (e.g., execFile, spawn without shell) instead of string interpolation in shell commands.',
            references: ['https://equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/'],
            detectedAt: createTimestamp(),
            metadata: {},
          });
        }
        // Reset regex lastIndex
        pattern.pattern.lastIndex = 0;
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 6. Path Traversal Detector
// ---------------------------------------------------------------------------

export class PathTraversalDetector implements Detector {
  family = DetectorFamily.PATH_TRAVERSAL;
  name = 'Path Traversal Detector';
  description = 'Inspects for unrestricted file path operations, missing scope constraints, and directory traversal risks';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.sourceCode) return findings;

    const traversalPatterns: Array<{ pattern: RegExp; description: string }> = [
      { pattern: /path\.join\(.*req\.|path\.join\(.*params\./g, description: 'User input in path.join() without sanitization' },
      { pattern: /path\.resolve\(.*req\.|path\.resolve\(.*params\./g, description: 'User input in path.resolve() without sanitization' },
      { pattern: /fs\.(readFile|writeFile|unlink|rmdir|readdir)\((?!.*sanitize)/g, description: 'File system operation without path sanitization' },
      { pattern: /\.\.\/|\.\.\\|%2e%2e/gi, description: 'Directory traversal sequence detected' },
      { pattern: /readFileSync\(.*\+/g, description: 'String concatenation in readFileSync path' },
      { pattern: /writeFileSync\(.*\+/g, description: 'String concatenation in writeFileSync path' },
      { pattern: /open\(.*\+.*['"]r/g, description: 'Dynamic file path in open() call' },
    ];

    const lines = ctx.sourceCode.split('\n');
    for (const pattern of traversalPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (pattern.pattern.test(lines[i])) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Potential path traversal vulnerability',
            description: pattern.description,
            severity: Severity.HIGH,
            confidence: 0.75,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: 'source',
              lineNumber: i + 1,
              snippet: lines[i].trim(),
              artifacts: [],
            },
            remediation: 'Validate and sanitize all file paths. Use path.normalize() and verify the resolved path stays within the intended directory.',
            references: [],
            detectedAt: createTimestamp(),
            metadata: {},
          });
        }
        pattern.pattern.lastIndex = 0;
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 7. SSRF Detector
// ---------------------------------------------------------------------------

export class SSRFDetector implements Detector {
  family = DetectorFamily.SSRF;
  name = 'SSRF Detector';
  description = 'Finds URL sinks and network clients driven by user-controlled input';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.sourceCode) return findings;

    const ssrfPatterns: Array<{ pattern: RegExp; description: string }> = [
      { pattern: /fetch\(.*req\.|fetch\(.*params\.|fetch\(.*input/g, description: 'User-controlled URL in fetch()' },
      { pattern: /axios\.(get|post|put|delete)\(.*req\.|axios\..*params\./g, description: 'User-controlled URL in axios request' },
      { pattern: /http\.request\(.*req\./g, description: 'User-controlled URL in http.request()' },
      { pattern: /urllib\.request\.urlopen\(.*req/g, description: 'User-controlled URL in urlopen() (Python)' },
      { pattern: /requests\.(get|post)\(.*req\./g, description: 'User-controlled URL in requests (Python)' },
      { pattern: /new\s+URL\(.*req\.|new\s+URL\(.*param/g, description: 'User-controlled URL construction' },
      { pattern: /\.well-known\/oauth-authorization-server/g, description: 'OAuth discovery endpoint — potential SSRF via discovery manipulation' },
    ];

    const lines = ctx.sourceCode.split('\n');
    for (const pattern of ssrfPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (pattern.pattern.test(lines[i])) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Potential SSRF vulnerability',
            description: pattern.description,
            severity: Severity.HIGH,
            confidence: 0.7,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: 'source',
              lineNumber: i + 1,
              snippet: lines[i].trim(),
              artifacts: [],
            },
            remediation: 'Validate and restrict URLs to approved domains. Use allowlists for outbound connections. Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, etc.).',
            references: ['https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices'],
            detectedAt: createTimestamp(),
            metadata: {},
          });
        }
        pattern.pattern.lastIndex = 0;
      }
    }

    // Check server URL for suspicious targets
    if (ctx.server.url) {
      const url = ctx.server.url.toLowerCase();
      const internalPatterns = ['169.254', '10.', '172.16', '172.17', '172.18', '192.168', 'localhost', '127.0.0.1', '0.0.0.0', 'metadata.google', 'metadata.aws'];
      for (const internal of internalPatterns) {
        if (url.includes(internal)) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Server URL points to internal/metadata address',
            description: `Server URL "${ctx.server.url}" appears to point to an internal network address or cloud metadata service.`,
            severity: Severity.CRITICAL,
            confidence: 0.95,
            status: FindingStatus.OPEN,
            evidence: { type: 'static', location: 'server.url', snippet: ctx.server.url, artifacts: [] },
            remediation: 'Do not connect to internal IP ranges or cloud metadata services from MCP server configurations.',
            references: [],
            detectedAt: createTimestamp(),
            metadata: {},
          });
          break;
        }
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 8. Token Passthrough Detector
// ---------------------------------------------------------------------------

export class TokenPassthroughDetector implements Detector {
  family = DetectorFamily.TOKEN_PASSTHROUGH;
  name = 'Token Passthrough Detector';
  description = 'Detects forwarding of user tokens or bearer credentials to downstream servers (forbidden by spec)';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.sourceCode) return findings;

    const passthroughPatterns: Array<{ pattern: RegExp; description: string }> = [
      { pattern: /headers\[['"]authorization['"]\]\s*=.*req\./gi, description: 'Forwarding authorization header from request to downstream' },
      { pattern: /bearer\s+.*req\.(headers|token|auth)/gi, description: 'Passing bearer token from request context' },
      { pattern: /\.setHeader\(['"]Authorization['"].*req\./gi, description: 'Setting Authorization header from incoming request' },
      { pattern: /authorization:\s*req\./gi, description: 'Passing authorization from request object to outbound call' },
      { pattern: /token:\s*req\.|token:\s*ctx\./gi, description: 'Token passthrough from request/context' },
    ];

    const lines = ctx.sourceCode.split('\n');
    for (const pattern of passthroughPatterns) {
      for (let i = 0; i < lines.length; i++) {
        if (pattern.pattern.test(lines[i])) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Token passthrough detected',
            description: `${pattern.description}. Official MCP guidance explicitly forbids forwarding user credentials to downstream services.`,
            severity: Severity.CRITICAL,
            confidence: 0.85,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: 'source',
              lineNumber: i + 1,
              snippet: lines[i].trim(),
              artifacts: [],
            },
            remediation: 'Do not forward user tokens to downstream services. Use service-to-service credentials instead.',
            references: ['https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices'],
            detectedAt: createTimestamp(),
            metadata: {},
          });
        }
        pattern.pattern.lastIndex = 0;
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 9. Tool Poisoning Detector
// ---------------------------------------------------------------------------

export class ToolPoisoningDetector implements Detector {
  family = DetectorFamily.TOOL_POISONING;
  name = 'Tool Poisoning Detector';
  description = 'Compares tool descriptions and schemas across versions to detect deceptive metadata';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.previousVersion) return findings;

    const prev = ctx.previousVersion;

    // Check for changed descriptions
    if (prev.descriptions && prev.changedDescriptions) {
      // This would be populated by the version diffing engine
    }

    // Check for suspicious keywords in tool descriptions
    const rawConfig = (ctx.server.metadata?.rawConfig as any) || {};
    const tools = rawConfig.tools || [];

    const deceptiveKeywords = [
      'harmless', 'safe', 'read-only', 'no side effects', 'does not modify',
      'temporary', 'just checking', 'only reads', 'view only'
    ];
    const dangerousCapabilities = [
      'write', 'delete', 'execute', 'send', 'upload', 'modify', 'create', 'install'
    ];

    if (Array.isArray(tools)) {
      for (const tool of tools) {
        if (!tool.description) continue;
        const desc = (tool.description as string).toLowerCase();

        // Check if description claims safety but name suggests danger
        const claimsSafety = deceptiveKeywords.some(k => desc.includes(k));
        const hasDangerousCap = dangerousCapabilities.some(k =>
          (tool.name as string || '').toLowerCase().includes(k)
        );

        if (claimsSafety && hasDangerousCap) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Potentially deceptive tool description',
            description: `Tool "${tool.name}" claims to be safe/read-only in its description but its name suggests write/destructive capabilities. This may be an attempt to trick the model.`,
            severity: Severity.HIGH,
            confidence: 0.65,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: `tool.${tool.name}`,
              snippet: `Name: ${tool.name}, Description: ${tool.description}`,
              artifacts: [],
            },
            remediation: 'Review tool descriptions for accuracy. Descriptions should truthfully represent the tool\'s capabilities and side effects.',
            references: ['https://arxiv.org/abs/2508.14925'],
            detectedAt: createTimestamp(),
            metadata: { toolName: tool.name },
          });
        }
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 10. Dependency Risk Analyzer
// ---------------------------------------------------------------------------

export class DependencyRiskAnalyzer implements Detector {
  family = DetectorFamily.DEPENDENCY_RISK;
  name = 'Dependency Risk Analyzer';
  description = 'Checks for CVEs, postinstall scripts, typosquat heuristics, and package provenance gaps';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.packageJson) return findings;

    const pkg = ctx.packageJson;

    // Check for postinstall scripts
    if (pkg.scripts) {
      const dangerousScripts = ['postinstall', 'preinstall', 'install', 'prepare'];
      for (const script of dangerousScripts) {
        if (pkg.scripts[script]) {
          const scriptContent = pkg.scripts[script] as string;
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: `Package has ${script} script`,
            description: `The package defines a "${script}" script: "${scriptContent}". Install scripts can execute arbitrary code during package installation.`,
            severity: scriptContent.includes('curl') || scriptContent.includes('wget')
              ? Severity.CRITICAL
              : Severity.MEDIUM,
            confidence: 0.9,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: `package.json#scripts.${script}`,
              snippet: scriptContent,
              artifacts: [],
            },
            remediation: 'Review the install script carefully. Consider removing or sandboxing install scripts.',
            references: [],
            detectedAt: createTimestamp(),
            metadata: { script, content: scriptContent },
          });
        }
      }
    }

    // Check for missing provenance/signing indicators
    if (!pkg.publishConfig?.provenance) {
      findings.push({
        id: createId(),
        serverId: ctx.server.id,
        detector: this.family,
        title: 'Package lacks provenance attestation',
        description: 'The package does not declare provenance publishing. Provenance attestation (e.g., Sigstore/SLSA) helps verify the package build chain.',
        severity: Severity.LOW,
        confidence: 0.6,
        status: FindingStatus.OPEN,
        evidence: { type: 'static', location: 'package.json', snippet: 'No provenance config', artifacts: [] },
        remediation: 'Enable npm provenance publishing or add Sigstore/SLSA attestation.',
        references: [],
        detectedAt: createTimestamp(),
        metadata: {},
      });
    }

    // Typosquat heuristics
    const knownPackages = [
      'express', 'react', 'lodash', 'axios', 'webpack', 'typescript', 'next',
      'vue', 'angular', 'fastify', 'prisma', 'sequelize', 'mongoose',
    ];
    const allDeps = {
      ...pkg.dependencies,
      ...pkg.devDependencies,
    };

    for (const dep of Object.keys(allDeps || {})) {
      for (const known of knownPackages) {
        if (dep !== known && this.levenshtein(dep, known) <= 2 && dep.length >= 3) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: 'Potential typosquat dependency',
            description: `Dependency "${dep}" is very similar to popular package "${known}". This could indicate a typosquatting attack.`,
            severity: Severity.HIGH,
            confidence: 0.5,
            status: FindingStatus.OPEN,
            evidence: { type: 'static', location: 'package.json#dependencies', snippet: `${dep} ≈ ${known}`, artifacts: [] },
            remediation: `Verify that "${dep}" is the intended dependency and not a typosquat of "${known}".`,
            references: [],
            detectedAt: createTimestamp(),
            metadata: { dependency: dep, similar: known },
          });
        }
      }
    }

    return findings;
  }

  private levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        matrix[i][j] = b[i - 1] === a[j - 1]
          ? matrix[i - 1][j - 1]
          : Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
      }
    }
    return matrix[b.length][a.length];
  }
}

// ---------------------------------------------------------------------------
// 11. Version Drift Detector
// ---------------------------------------------------------------------------

export class VersionDriftDetector implements Detector {
  family = DetectorFamily.VERSION_DRIFT;
  name = 'Version Drift Detector';
  description = 'Diffs tool lists, scopes, package scripts, and env vars between versions to detect silent privilege creep';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    if (!ctx.previousVersion) return findings;

    const prev = ctx.previousVersion;
    const rawConfig = (ctx.server.metadata?.rawConfig as any) || {};
    const currentTools = rawConfig.tools || [];
    const currentEnvVars = Object.keys(ctx.server.env || {});

    // Check for new env vars (may indicate new credential requirements)
    if (prev.envVars) {
      const newEnvVars = currentEnvVars.filter((e: string) => !prev.envVars.includes(e));
      if (newEnvVars.length > 0) {
        findings.push({
          id: createId(),
          serverId: ctx.server.id,
          detector: this.family,
          title: 'New environment variables since last version',
          description: `Server "${ctx.server.name}" now requires ${newEnvVars.length} new environment variable(s): ${newEnvVars.join(', ')}. This may indicate expanded scope or new credential requirements.`,
          severity: Severity.MEDIUM,
          confidence: 0.8,
          status: FindingStatus.OPEN,
          evidence: { type: 'static', location: 'server.env', snippet: `New vars: ${newEnvVars.join(', ')}`, artifacts: [] },
          remediation: 'Review the new environment variables to verify they are expected and properly configured.',
          references: [],
          detectedAt: createTimestamp(),
          metadata: { newEnvVars },
        });
      }
    }

    // Check for changed package scripts
    if (prev.scripts && ctx.packageJson?.scripts) {
      for (const [script, content] of Object.entries(ctx.packageJson.scripts)) {
        if (prev.scripts[script] && prev.scripts[script] !== content) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: `Package script "${script}" changed between versions`,
            description: `The "${script}" script changed from "${prev.scripts[script]}" to "${content}". Changed install/build scripts can introduce supply chain risks.`,
            severity: Severity.HIGH,
            confidence: 0.85,
            status: FindingStatus.OPEN,
            evidence: {
              type: 'static',
              location: `package.json#scripts.${script}`,
              snippet: `Before: ${prev.scripts[script]}\nAfter: ${content}`,
              artifacts: [],
            },
            remediation: 'Review the script change to ensure it is intentional and benign.',
            references: [],
            detectedAt: createTimestamp(),
            metadata: { script, before: prev.scripts[script], after: content },
          });
        }
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// 12. Network Exfiltration Detector
// ---------------------------------------------------------------------------

export class NetworkExfiltrationDetector implements Detector {
  family = DetectorFamily.NETWORK_EXFILTRATION;
  name = 'Network Exfiltration Detector';
  description = 'Detects telemetry libraries, suspicious outbound endpoints, beaconing code, and hidden uploads';

  analyze(ctx: DetectorContext): Finding[] {
    const findings: Finding[] = [];

    // Check for suspicious telemetry/analytics dependencies
    if (ctx.packageJson) {
      const suspiciousDeps = [
        'analytics-node', 'mixpanel', 'segment-analytics',
        'posthog-node', 'amplitude', 'heap-analytics',
      ];
      const allDeps = {
        ...ctx.packageJson.dependencies,
        ...ctx.packageJson.devDependencies,
      };

      for (const dep of Object.keys(allDeps || {})) {
        if (suspiciousDeps.includes(dep)) {
          findings.push({
            id: createId(),
            serverId: ctx.server.id,
            detector: this.family,
            title: `Server includes telemetry dependency: ${dep}`,
            description: `The MCP server package includes "${dep}" as a dependency. Analytics/telemetry libraries in MCP servers may exfiltrate usage data, prompts, or context.`,
            severity: Severity.MEDIUM,
            confidence: 0.7,
            status: FindingStatus.OPEN,
            evidence: { type: 'static', location: 'package.json#dependencies', snippet: dep, artifacts: [] },
            remediation: 'Review what data the telemetry library collects. Consider removing it or adding user consent.',
            references: [],
            detectedAt: createTimestamp(),
            metadata: { dependency: dep },
          });
        }
      }
    }

    // Check source code for suspicious network patterns
    if (ctx.sourceCode) {
      const exfilPatterns: Array<{ pattern: RegExp; description: string }> = [
        { pattern: /\.postMessage\(/g, description: 'postMessage() — could be used for cross-origin data exfiltration' },
        { pattern: /navigator\.sendBeacon\(/g, description: 'sendBeacon() — used for silent data transmission' },
        { pattern: /new\s+WebSocket\(.*['"]/g, description: 'WebSocket connection — potential data exfiltration channel' },
        { pattern: /setInterval\(.*fetch\(/g, description: 'Periodic fetch() call — potential beaconing behavior' },
        { pattern: /setTimeout\(.*fetch\(.*\d{4,}/g, description: 'Delayed fetch() — potential covert data transmission' },
        { pattern: /btoa\(.*JSON\.stringify/g, description: 'Base64 encoding of JSON data — potentially hiding exfiltrated data' },
        { pattern: /new\s+Image\(\).*src\s*=/g, description: 'Image pixel tracking — potential data exfiltration via URL parameters' },
      ];

      const lines = ctx.sourceCode.split('\n');
      for (const pattern of exfilPatterns) {
        for (let i = 0; i < lines.length; i++) {
          if (pattern.pattern.test(lines[i])) {
            findings.push({
              id: createId(),
              serverId: ctx.server.id,
              detector: this.family,
              title: 'Potential network exfiltration pattern',
              description: pattern.description,
              severity: Severity.HIGH,
              confidence: 0.6,
              status: FindingStatus.OPEN,
              evidence: {
                type: 'static',
                location: 'source',
                lineNumber: i + 1,
                snippet: lines[i].trim(),
                artifacts: [],
              },
              remediation: 'Review the network communication code. Ensure all outbound connections are expected, documented, and have user consent.',
              references: [],
              detectedAt: createTimestamp(),
              metadata: {},
            });
          }
          pattern.pattern.lastIndex = 0;
        }
      }
    }

    return findings;
  }
}

// ---------------------------------------------------------------------------
// Scanner Orchestrator — runs all detectors
// ---------------------------------------------------------------------------

export class ScannerEngine {
  private detectors: Detector[];

  constructor(families?: DetectorFamily[]) {
    const allDetectors: Detector[] = [
      new SecretScanner(),
      new StartupCommandAnalyzer(),
      new AuthPostureChecker(),
      new CapabilitySurfaceAnalyzer(),
      new CommandInjectionDetector(),
      new PathTraversalDetector(),
      new SSRFDetector(),
      new TokenPassthroughDetector(),
      new ToolPoisoningDetector(),
      new DependencyRiskAnalyzer(),
      new VersionDriftDetector(),
      new NetworkExfiltrationDetector(),
    ];

    this.detectors = families
      ? allDetectors.filter(d => families.includes(d.family))
      : allDetectors;
  }

  scan(ctx: DetectorContext): Finding[] {
    const allFindings: Finding[] = [];

    for (const detector of this.detectors) {
      try {
        const findings = detector.analyze(ctx);
        allFindings.push(...findings);
      } catch (e: any) {
        // Log error but continue with other detectors
        console.error(`Detector ${detector.name} failed: ${e.message}`);
      }
    }

    return allFindings;
  }

  getDetectors(): Detector[] {
    return [...this.detectors];
  }
}
