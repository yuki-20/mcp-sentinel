// ============================================================================
// Collector Service — Public API
// ============================================================================

export {
  ClaudeDesktopParser,
  CursorParser,
  VSCodeParser,
  ClaudeCodeParser,
  GenericParser,
  discoverAllClients,
  ConfigWatcher,
} from './parsers';
export type { ParseResult, WatcherOptions } from './parsers';
