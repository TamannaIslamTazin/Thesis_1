/**
 * The logging seam that lets protocol logic leave the backend.
 *
 * WHY THIS EXISTS. Every service being moved into the SDK imports `logger` from
 * the backend's `utils/logger.ts`, which is winston — and winston is node-only
 * (fs, os, streams). It is not Prisma, not Credo and not Express, so it does
 * not show up in the obvious "what blocks a move" screen, yet it blocks every
 * one of them. This is that dependency inverted: the logic depends on a
 * four-method interface, and whoever composes it supplies the implementation.
 *
 * DELIBERATELY STRUCTURAL, NOT NOMINAL. `LoggerPort` is a plain interface, so
 * winston's `Logger` satisfies it by shape with no adapter, no wrapper and no
 * per-call allocation. The backend keeps passing the same winston instance it
 * always had, which is what makes the port a refactor rather than a rewrite of
 * how this system observes itself: identical level, identical message,
 * identical context object, identical transport.
 *
 * ABSENCE IS SILENCE, NOT A CRASH — and that is a considered exception to this
 * project's "refuse rather than guess" default. Refusing is right when the
 * missing input is a security control, because proceeding would assert
 * something unverified. A logger asserts nothing. A library that threw because
 * an integrator did not supply one would convert an observability gap into an
 * outage, so the default is {@link silentLogger} and the obligation moves to
 * the composition root: OUR backend adapters must always pass the real logger,
 * and there is a test asserting exactly that, because a service that quietly
 * logs into the void is the failure this file could plausibly cause.
 */

/** Structured context attached to a log line. Never concatenate into the message. */
export type LogContext = Record<string, unknown>;

/**
 * The logging surface protocol logic is allowed to depend on.
 *
 * Four levels because four are what the backend actually uses (measured:
 * info 103, warn 65, error 50, debug 4). Not a general logging abstraction —
 * no `child`, no transports, no formats. A narrow port is one an integrator can
 * satisfy in five lines; a wide one gets satisfied by pulling in winston, which
 * is the dependency this exists to remove.
 */
export interface LoggerPort {
  debug(message: string, context?: LogContext): void;
  info(message: string, context?: LogContext): void;
  warn(message: string, context?: LogContext): void;
  error(message: string, context?: LogContext): void;
}

/** Discards everything. The default when no logger is supplied. */
export const silentLogger: LoggerPort = Object.freeze({
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
});

/** One captured log line, in emission order. */
export interface CapturedLog {
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  context: LogContext | undefined;
}

/**
 * A logger that records instead of printing, so moved logic keeps its logging
 * under test.
 *
 * When a service moves out of the backend it stops being covered by whatever
 * asserted its winston output, and log lines are the thing this project
 * debugs incidents with. Losing them is a quiet, delayed cost no ordinary test
 * would catch — so the replacement for "it logged" has to be assertable, and
 * this is it.
 */
export function collectLogs(): LoggerPort & { readonly entries: CapturedLog[] } {
  const entries: CapturedLog[] = [];
  const record =
    (level: CapturedLog['level']) => (message: string, context?: LogContext) => {
      entries.push({ level, message, context });
    };
  return {
    entries,
    debug: record('debug'),
    info: record('info'),
    warn: record('warn'),
    error: record('error'),
  };
}
