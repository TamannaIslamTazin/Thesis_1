/**
 * THE LOGGER PORT DOES NOT CHANGE WHAT THIS SYSTEM OBSERVES ABOUT ITSELF.
 *
 * `LoggerPort` (steno #350) exists so protocol logic can leave the backend
 * without dragging winston — a node-only dependency — into a React Native
 * bundle. The whole value of that move rests on one property: routing a call
 * through the port must produce the SAME log line winston produced before.
 *
 * WHY THIS NEEDS A TEST AT ALL, when the port is "just an interface". Logging
 * is how this project debugs incidents. A port that silently dropped the
 * structured context, flattened it into the message, lost `defaultMeta.service`
 * or downgraded a level would cost nothing today and cost everything during the
 * first incident after it shipped — a quiet, delayed failure that no ordinary
 * behavioural test would catch, because every assertion about the CODE would
 * still pass. So the equivalence is asserted directly, against real winston
 * output captured from a real transport.
 *
 * The tests below deliberately capture winston's own emitted object rather than
 * a stringified line: the fields are what queries filter on in an incident, and
 * a string comparison would pass while a field quietly changed type.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Transport from 'winston-transport';
import { silentLogger, collectLogs, type LoggerPort } from '@ssi-healthcare/shared';
import { logger } from '../../src/utils/logger.js';

/** Captures the objects winston actually emits, after formats are applied. */
class CapturingTransport extends Transport {
  public readonly seen: Record<string, unknown>[] = [];
  override log(info: Record<string, unknown>, next: () => void): void {
    this.seen.push({ ...info });
    next();
  }
}

describe('LoggerPort does not change log output', () => {
  let capture: CapturingTransport;

  beforeEach(() => {
    capture = new CapturingTransport();
    logger.add(capture);
  });

  afterEach(() => {
    logger.remove(capture);
  });

  /**
   * The emitted record and its SERIALIZED line, both minus the timestamp.
   *
   * Winston puts the finished line on a `Symbol(message)` property, and that
   * line embeds its own timestamp — so two calls milliseconds apart differ
   * there and nowhere else. Stripping the timestamp from BOTH levels compares
   * the thing an aggregator actually ingests, field by field, instead of
   * discarding the serialized form and asserting only on the pre-format object.
   */
  const comparable = (entry: Record<string, unknown>) => {
    const { timestamp, ...rest } = entry;
    expect(typeof timestamp).toBe('string');

    // Object spread copies enumerable SYMBOL keys too, so winston's serialized
    // line survives into `rest` carrying its own embedded timestamp. Parse it,
    // drop the timestamp, and compare the parsed form instead of the raw string.
    const symbols = Object.getOwnPropertySymbols(rest);
    const messageSymbol = symbols.find((s) => s.toString() === 'Symbol(message)');
    expect(messageSymbol).toBeDefined();

    const raw = (rest as unknown as Record<symbol, string>)[messageSymbol!];
    const serialized = JSON.parse(raw) as Record<string, unknown>;
    delete serialized.timestamp;

    for (const s of symbols) delete (rest as unknown as Record<symbol, unknown>)[s];

    return { ...rest, serialized };
  };

  it('emits an IDENTICAL record whether called directly or through the port', () => {
    const context = { holderDid: 'did:cheqd:bdhealthtestnet:abc', attemptCount: 3 };

    // The adapter shape every moved service will use: the same instance,
    // narrowed to the port. Nothing wraps it.
    const asPort: LoggerPort = logger;

    logger.warn('Professional authority REFUSED', context);
    asPort.warn('Professional authority REFUSED', context);

    expect(capture.seen).toHaveLength(2);
    const [direct, viaPort] = capture.seen;
    expect(comparable(viaPort!)).toEqual(comparable(direct!));
  });

  it('preserves the structured context as FIELDS, not concatenated into the message', () => {
    const asPort: LoggerPort = logger;
    asPort.error('Revocation status could not be established', {
      statusListCredential: 'did:cheqd:bdhealthtestnet:list#3',
      index: 42,
    });

    const [entry] = capture.seen;
    expect(entry!.message).toBe('Revocation status could not be established');
    // Queryable fields, at the top level, with their types intact.
    expect(entry!.statusListCredential).toBe('did:cheqd:bdhealthtestnet:list#3');
    expect(entry!.index).toBe(42);
  });

  it('preserves defaultMeta.service, which distinguishes emitters in aggregation', () => {
    const asPort: LoggerPort = logger;
    asPort.info('Professional authority established');
    expect(capture.seen[0]!.service).toBe('ssi-healthcare-backend');
  });

  it.each(['debug', 'info', 'warn', 'error'] as const)(
    'routes %s at its own level, never downgraded',
    (level) => {
      const asPort: LoggerPort = logger;
      // `debug` sits below the configured level, so assert on what reaches the
      // transport rather than assuming every call is emitted.
      asPort[level](`probe-${level}`);
      const entry = capture.seen.find((e) => e.message === `probe-${level}`);
      if (entry) expect(entry.level).toBe(level);
      else expect(level).toBe('debug');
    },
  );
});

describe('the port fails safe when nobody supplies a logger', () => {
  it('silentLogger accepts every level without throwing', () => {
    // A library that threw because an integrator passed no logger would turn an
    // observability gap into an outage. Silence is the deliberate default.
    expect(() => {
      silentLogger.debug('a');
      silentLogger.info('b', { k: 1 });
      silentLogger.warn('c');
      silentLogger.error('d', { k: 2 });
    }).not.toThrow();
  });

  it('silentLogger is frozen, so a caller cannot install a sink on the shared default', () => {
    expect(Object.isFrozen(silentLogger)).toBe(true);
  });

  it('collectLogs records level, message and context in emission order', () => {
    // This is what keeps moved logic's logging ASSERTABLE once it no longer has
    // a winston transport to observe. Without it, "it still logs" becomes
    // unfalsifiable at exactly the moment the code leaves this package.
    const log = collectLogs();
    log.warn('refused', { reason: 'licence-expired' });
    log.info('established');

    expect(log.entries).toEqual([
      { level: 'warn', message: 'refused', context: { reason: 'licence-expired' } },
      { level: 'info', message: 'established', context: undefined },
    ]);
  });
});

describe('the composition root keeps its obligation', () => {
  it('the backend logger satisfies LoggerPort at runtime, not just at compile time', () => {
    // `src/utils/logger.ts` asserts this in the type system. That assertion is
    // erased at runtime, so a winston upgrade could satisfy tsc and still ship
    // a missing method. Check the shape that will actually be called.
    const asPort: LoggerPort = logger;
    for (const level of ['debug', 'info', 'warn', 'error'] as const) {
      expect(typeof asPort[level]).toBe('function');
    }
  });

  it('the real logger is NOT the silent one, so adapters cannot log into the void', () => {
    // The failure this file exists to prevent: an adapter defaulting to
    // `silentLogger` because it forgot to pass the real one, and every log line
    // in a moved service disappearing without a single test going red.
    const asPort: LoggerPort = logger;
    expect(asPort).not.toBe(silentLogger);
  });
});
