/**
 * The error seam's two load-bearing properties.
 *
 * These are NOT tests that moved logic still does what it did — the suites that
 * already cover each refusal do that. `SsiError` is genuinely new code, and two
 * of its properties are the kind that fail silently and only in a built bundle,
 * which is precisely where no existing test looks:
 *
 *   1. IDENTITY SURVIVES MODULE DUPLICATION. `tsup` builds each SDK entry point
 *      with `splitting: false`, so a class declared inside the SDK is copied per
 *      entry and `instanceof` between two copies is false. The brand is
 *      `Symbol.for`, which is registry-global, so it is not. The second test
 *      below simulates the duplicate directly rather than trusting that
 *      `shared` will stay `external` forever.
 *
 *   2. AN UNKNOWN ERROR'S MESSAGE IS NEVER RELAYED. `serialiseError` is what a
 *      boundary hands a client. A thrown value from a driver or a parser
 *      routinely carries a query, an absolute path or a schema in its message.
 *      Fail closed: anything unrecognised collapses to a fixed string.
 */

import { describe, it, expect } from 'vitest';
import { SsiError, isSsiError, serialiseError } from '@ssi-healthcare/shared';

describe('SsiError', () => {
  it('carries code, message, status and details', () => {
    const error = new SsiError('DID_CREATION_FAILED', 'nope', 400, { did: 'did:cheqd:x' });
    expect(error.code).toBe('DID_CREATION_FAILED');
    expect(error.message).toBe('nope');
    expect(error.statusCode).toBe(400);
    expect(error.details).toEqual({ did: 'did:cheqd:x' });
  });

  it('defaults to 500 — an unclassified refusal is ours, not the caller\'s', () => {
    expect(new SsiError('X', 'y').statusCode).toBe(500);
  });

  it('is a real Error, so a catch-all handler and a stack trace still work', () => {
    const error = new SsiError('X', 'y');
    expect(error).toBeInstanceOf(Error);
    expect(typeof error.stack).toBe('string');
  });

  it('reports the subclass name, so a backend AppError still says AppError', () => {
    class AppError extends SsiError {}
    expect(new AppError('X', 'y').name).toBe('AppError');
    expect(new SsiError('X', 'y').name).toBe('SsiError');
  });

  it('attaches cause only when one is supplied', () => {
    const root = new Error('root');
    expect((new SsiError('X', 'y', 500, undefined, { cause: root }) as { cause?: unknown }).cause)
      .toBe(root);
    expect('cause' in new SsiError('X', 'y')).toBe(false);
  });
});

describe('isSsiError', () => {
  it('accepts an SsiError and its subclasses', () => {
    class AppError extends SsiError {}
    expect(isSsiError(new SsiError('X', 'y'))).toBe(true);
    expect(isSsiError(new AppError('X', 'y'))).toBe(true);
  });

  it('accepts an error from a DUPLICATED copy of the class, which instanceof does not', () => {
    // Exactly what a bundler produces when `shared` stops being external: a
    // structurally identical class, branded from the global symbol registry,
    // whose prototype chain has nothing to do with ours.
    const brand = Symbol.for('@ssi-healthcare/shared#SsiError');
    class DuplicatedSsiError extends Error {
      readonly [brand] = true;
      constructor(
        public readonly code: string,
        message: string,
        public readonly statusCode = 500,
      ) {
        super(message);
      }
    }
    const fromOtherCopy = new DuplicatedSsiError('DID_CREATION_FAILED', 'nope', 400);

    expect(fromOtherCopy instanceof SsiError).toBe(false); // the trap
    expect(isSsiError(fromOtherCopy)).toBe(true); // the failsafe
  });

  it('rejects everything unbranded, including look-alikes', () => {
    for (const value of [
      undefined,
      null,
      'DID_CREATION_FAILED',
      42,
      new Error('plain'),
      { code: 'DID_CREATION_FAILED', message: 'nope', statusCode: 400 },
      Object.create(null),
    ]) {
      expect(isSsiError(value)).toBe(false);
    }
  });
});

describe('serialiseError', () => {
  it('relays code, message and details for a recognised refusal', () => {
    const error = new SsiError('CONSENT_EXPIRED', 'expired', 403, { at: 'yesterday' });
    expect(serialiseError(error)).toEqual({
      code: 'CONSENT_EXPIRED',
      message: 'expired',
      details: { at: 'yesterday' },
    });
  });

  it('omits details entirely rather than emitting undefined', () => {
    expect(serialiseError(new SsiError('X', 'y'))).toEqual({ code: 'X', message: 'y' });
    expect('details' in serialiseError(new SsiError('X', 'y'))).toBe(false);
  });

  it('never relays an unrecognised error\'s message', () => {
    const leaky = new Error(
      'SELECT * FROM "Patient" WHERE nid = $1 -- /home/ahsan/secret/db.sqlite',
    );
    const serialised = serialiseError(leaky);
    expect(serialised).toEqual({
      code: 'INTERNAL_ERROR',
      message: 'An unexpected error occurred.',
    });
    expect(JSON.stringify(serialised)).not.toContain('Patient');
    expect(JSON.stringify(serialised)).not.toContain('/home/ahsan');
  });

  it('never relays a thrown non-Error, however it is shaped', () => {
    for (const value of ['raw string secret', { message: 'object secret' }, null]) {
      expect(serialiseError(value)).toEqual({
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred.',
      });
    }
  });

  it('does not carry stack or cause onto the wire', () => {
    const error = new SsiError('X', 'y', 400, undefined, { cause: new Error('upstream body') });
    const serialised = serialiseError(error) as unknown as Record<string, unknown>;
    expect('stack' in serialised).toBe(false);
    expect('cause' in serialised).toBe(false);
    expect('statusCode' in serialised).toBe(false);
  });
});
