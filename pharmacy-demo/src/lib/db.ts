/**
 * The pharmacy's data layer — SQLite, in-process, no external service.
 *
 * WHY IT LIVES IN THE MONOLITH. The pharmacy is deliberately ONE container:
 * counter UI, business logic and stock data. A pharmacy PC is a single machine
 * behind a counter, so splitting it into services would add deployment surface
 * for no operational gain. `node:sqlite` is built into Node 22, so there is no
 * native module to compile and nothing to install in the image.
 *
 * WHAT THIS STORE IS NOT. It holds no patient data and no credential bytes. The
 * prescription is verified elsewhere and only its ID and the resulting token are
 * kept, so a stolen pharmacy database exposes stock levels, not people.
 */
import { DatabaseSync } from 'node:sqlite';

const DB_PATH = process.env.PHARMACY_DB ?? '/data/pharmacy.sqlite';

export interface Medicine {
  readonly id: number;
  readonly name: string;
  readonly strength: string;
  readonly form: string;
  readonly unitPrice: number;
  readonly stock: number;
  readonly storeArea: string;
}

/** What the dispense COMPUTES, before the row exists. */
export interface DispenseLineInput {
  readonly medicineId: number;
  readonly name: string;
  readonly quantity: number;
  readonly unitPrice: number;
  readonly lineTotal: number;
}

/**
 * What a READ returns: the input plus two fields only the shelf knows.
 *
 * Split from the input on purpose — availability and store area are read from
 * `medicines` at read time and are not part of the dispense decision, so making
 * the dispense produce them would mean it inventing values it has not read.
 */
export interface DispenseLine extends DispenseLineInput {
  readonly availability: number;
  readonly storeArea: string;
}

export interface Dispense {
  readonly token: number;
  readonly prescriptionId: string;
  readonly lines: readonly DispenseLine[];
  readonly total: number;
  readonly createdAt: string;
}

let db: DatabaseSync | null = null;

/** Opened once per process; Next.js route handlers share the module instance. */
export function getDb(): DatabaseSync {
  if (db) return db;
  const handle = new DatabaseSync(DB_PATH);
  handle.exec(`
    CREATE TABLE IF NOT EXISTS medicines (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      name        TEXT    NOT NULL,
      strength    TEXT    NOT NULL DEFAULT '',
      form        TEXT    NOT NULL DEFAULT '',
      unit_price  REAL    NOT NULL,
      stock       INTEGER NOT NULL DEFAULT 0,
      store_area  TEXT    NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS dispenses (
      token           INTEGER PRIMARY KEY AUTOINCREMENT,
      prescription_id TEXT    NOT NULL UNIQUE,
      total           REAL    NOT NULL,
      created_at      TEXT    NOT NULL,
      paid            INTEGER NOT NULL DEFAULT 0,
      paid_at         TEXT
    );
    CREATE TABLE IF NOT EXISTS dispense_lines (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      token       INTEGER NOT NULL REFERENCES dispenses(token),
      medicine_id INTEGER NOT NULL,
      name        TEXT    NOT NULL,
      quantity    INTEGER NOT NULL,
      unit_price  REAL    NOT NULL
    );
    -- THIS PHARMACY'S OWN IDENTITY, once it has paired with an L1 officer.
    --
    -- public_key_multibase is the Ed25519 key sent at claim time; it becomes
    -- #key-officer-2 on the institutional DID (see institutionMinting.ts), which
    -- is what makes the institution a 2-of-N it actually controls rather than a
    -- 1-of-1 held only by the ministry.
    --
    -- The PRIVATE key is stored ENCRYPTED under a passphrase the admin sets at
    -- pairing. Node's own scrypt + AES-256-GCM, not a bespoke scheme: this is the
    -- key that will sign this pharmacy's dispensing records, so it is exactly the
    -- wrong place to hand-roll.
    --
    -- Single row, enforced by the CHECK on id. A pharmacy has ONE identity;
    -- a second row would mean two DIDs claiming to be the same premises.
    --
    -- NOTE: this comment uses -- and NOT backticks. A backtick inside this
    -- template literal TERMINATES THE STRING, which is a syntax error the
    -- compiler reports at a line far from the cause.
    CREATE TABLE IF NOT EXISTS pharmacy_identity (
      id                    INTEGER PRIMARY KEY CHECK (id = 1),
      public_key_multibase  TEXT    NOT NULL,
      private_key_ciphertext TEXT   NOT NULL,
      kdf_salt              TEXT    NOT NULL,
      created_at            TEXT    NOT NULL,
      -- Set once the officer has confirmed and the DID exists.
      did                   TEXT
    );
    CREATE TABLE IF NOT EXISTS accounts (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL CHECK (role IN ('user', 'admin')),
      display_name  TEXT    NOT NULL DEFAULT '',
      created_at    TEXT    NOT NULL
    );
  `);

  // Idempotent column adds for databases created before A1.
  //
  // `CREATE TABLE IF NOT EXISTS` cannot add a column to a table that already
  // exists, so a counter that has been running keeps its old shape and the new
  // columns must be added here. Each ALTER is wrapped because the only failure
  // expected is "duplicate column name", which means it is already done.
  for (const statement of [
    'ALTER TABLE dispenses ADD COLUMN dispense_id TEXT',
    'ALTER TABLE dispenses ADD COLUMN abandoned_at TEXT',
    'ALTER TABLE dispenses ADD COLUMN abandoned_reason TEXT',
  ]) {
    try {
      handle.exec(statement);
    } catch {
      // Already present. Nothing to do, and nothing to report.
    }
  }

  seedIfEmpty(handle);
  db = handle;
  return db;
}

/**
 * Seed on first open, never overwrite.
 *
 * A pharmacy that reseeded on every boot would silently resurrect stock that
 * was dispensed, so this runs only when the table is genuinely empty.
 */
function seedIfEmpty(handle: DatabaseSync): void {
  const row = handle.prepare('SELECT COUNT(*) AS n FROM medicines').get() as { n: number };
  if (row.n > 0) return;

  const insert = handle.prepare(
    'INSERT INTO medicines (name, strength, form, unit_price, stock, store_area) VALUES (?, ?, ?, ?, ?, ?)',
  );
  const seed: ReadonlyArray<[string, string, string, number, number, string]> = [
    ['Paracetamol', '500 mg', 'Tablet', 1.2, 500, 'A1'],
    ['Amoxicillin', '500 mg', 'Capsule', 6.5, 240, 'A2'],
    ['Metformin', '500 mg', 'Tablet', 2.0, 380, 'B1'],
    ['Amlodipine', '5 mg', 'Tablet', 1.8, 300, 'B2'],
    ['Omeprazole', '20 mg', 'Capsule', 4.0, 210, 'B3'],
    ['Salbutamol Inhaler', '100 mcg', 'Inhaler', 145.0, 40, 'Cold C1'],
    ['Cetirizine', '10 mg', 'Tablet', 1.5, 420, 'A3'],
    ['Azithromycin', '500 mg', 'Tablet', 18.0, 150, 'A4'],
    ['Losartan', '50 mg', 'Tablet', 3.2, 260, 'B4'],
    ['Oral Rehydration Salts', '', 'Sachet', 5.0, 600, 'A5'],
  ];
  for (const [name, strength, form, price, stock, area] of seed) {
    insert.run(name, strength, form, price, stock, area);
  }
  console.log(`[pharmacy] seeded ${seed.length} medicines`);
}

export function listMedicines(): Medicine[] {
  return getDb()
    .prepare('SELECT id, name, strength, form, unit_price AS unitPrice, stock, store_area AS storeArea FROM medicines ORDER BY name')
    .all() as unknown as Medicine[];
}

export function addMedicine(input: {
  name: string;
  strength: string;
  form: string;
  unitPrice: number;
  stock: number;
  storeArea: string;
}): Medicine {
  const info = getDb()
    .prepare('INSERT INTO medicines (name, strength, form, unit_price, stock, store_area) VALUES (?, ?, ?, ?, ?, ?)')
    .run(input.name, input.strength, input.form, input.unitPrice, input.stock, input.storeArea);
  return {
    id: Number(info.lastInsertRowid),
    ...input,
  };
}

/** Resolve a prescribed name to a stocked medicine, case-insensitively. */
export function findMedicine(name: string): Medicine | null {
  const row = getDb()
    .prepare(
      'SELECT id, name, strength, form, unit_price AS unitPrice, stock, store_area AS storeArea FROM medicines WHERE lower(name) = lower(?)',
    )
    .get(name) as unknown as Medicine | undefined;
  return row ?? null;
}

/**
 * Record a dispense, decrement stock, and mint the token — atomically.
 *
 * THE TOKEN IS THE COUNTER'S QUEUE NUMBER, and it is the row's primary key, so
 * two counters cannot mint the same one. The prescription id is UNIQUE, which is
 * the single-use guarantee: a replay of the same verified prescription fails the
 * insert instead of dispensing twice.
 */
export function recordDispense(prescriptionId: string, lines: readonly DispenseLineInput[], dispenseId: string): number {
  const handle = getDb();
  const total = lines.reduce((sum, line) => sum + line.lineTotal, 0);
  const createdAt = new Date().toISOString();

  handle.exec('BEGIN');
  try {
    // dispense_id is the BACKEND's identifier for this dispense, stored so the
    // counter can later settle or abandon the right record. Without it the
    // counter knows only its own queue number, which the backend never sees as an
    // address (two pharmacies may each have a "token 1").
    const inserted = handle
      .prepare('INSERT INTO dispenses (prescription_id, total, created_at, dispense_id) VALUES (?, ?, ?, ?)')
      .run(prescriptionId, total, createdAt, dispenseId);
    const token = Number(inserted.lastInsertRowid);

    const addLine = handle.prepare(
      'INSERT INTO dispense_lines (token, medicine_id, name, quantity, unit_price) VALUES (?, ?, ?, ?, ?)',
    );
    const takeStock = handle.prepare('UPDATE medicines SET stock = stock - ? WHERE id = ?');
    for (const line of lines) {
      addLine.run(token, line.medicineId, line.name, line.quantity, line.unitPrice);
      takeStock.run(line.quantity, line.medicineId);
    }
    handle.exec('COMMIT');
    return token;
  } catch (error) {
    handle.exec('ROLLBACK');
    throw error;
  }
}

/**
 * Undo a mint that the ledger refused.
 *
 * WHY THIS EXISTS (A1, 27 Sep 2026). The token is now minted BEFORE the append,
 * so that the append can carry the queue number and the wallet can show it. That
 * reverses the old order, whose intent was "a counter that cannot report must not
 * dispense". The intent is preserved by this function: if the append fails, the
 * mint is undone here and the counter surfaces an error, so no token exists for a
 * dispense the ledger never recorded.
 *
 * It deletes the row rather than flagging it, because a voided token that stayed
 * in the table would still occupy the UNIQUE prescription_id and would make the
 * legitimate retry fail as a replay — turning a recoverable network fault into a
 * permanently undispensable prescription.
 */
export function voidDispense(token: number): void {
  const handle = getDb();
  handle.exec('BEGIN');
  try {
    const lines = handle
      .prepare('SELECT medicine_id AS medicineId, quantity FROM dispense_lines WHERE token = ?')
      .all(token) as unknown as Array<{ medicineId: string; quantity: number }>;
    const giveStock = handle.prepare('UPDATE medicines SET stock = stock + ? WHERE id = ?');
    for (const line of lines) giveStock.run(line.quantity, line.medicineId);
    handle.prepare('DELETE FROM dispense_lines WHERE token = ?').run(token);
    handle.prepare('DELETE FROM dispenses WHERE token = ?').run(token);
    handle.exec('COMMIT');
  } catch (error) {
    handle.exec('ROLLBACK');
    throw error;
  }
}

/**
 * The few facts the settlement path needs before it writes anything: which
 * backend dispense this is, how old the token is, and whether it is still open.
 *
 * The counter addresses the backend by DISPENSE ID, never by the queue number:
 * the queue number is local to one pharmacy, and two counters may each have a
 * "token 1". `createdAt` is returned so the caller can apply the 24-hour rule at
 * read time (A1 stage 4b) without a second query.
 */
export interface DispenseState {
  readonly dispenseId: string | null;
  readonly createdAt: string;
  readonly paid: boolean;
  readonly abandonedAt: string | null;
}

export function dispenseState(token: number): DispenseState | null {
  const row = getDb()
    .prepare(
      'SELECT dispense_id AS dispenseId, created_at AS createdAt, paid, abandoned_at AS abandonedAt FROM dispenses WHERE token = ?',
    )
    .get(token) as unknown as
    | { dispenseId: string | null; createdAt: string; paid: number; abandonedAt: string | null }
    | undefined;
  if (!row) return null;
  return { ...row, paid: row.paid === 1 };
}

/**
 * Close a token as not collected. Returns whether this call changed anything, so
 * a double tap is reported rather than silently repeated.
 *
 * The once-only guard is in the WHERE clause, which is the same shape `markPaid`
 * uses: a read-then-write would race with a second tap.
 */
export function markAbandoned(token: number, reason: 'declined'): boolean {
  const result = getDb()
    .prepare(
      'UPDATE dispenses SET abandoned_at = ?, abandoned_reason = ? WHERE token = ? AND paid = 0 AND abandoned_at IS NULL',
    )
    .run(new Date().toISOString(), reason, token);
  return Number(result.changes) > 0;
}

export function getDispense(token: number): Dispense | null {
  const head = getDb()
    .prepare('SELECT token, prescription_id AS prescriptionId, total, created_at AS createdAt FROM dispenses WHERE token = ?')
    .get(token) as unknown as Omit<Dispense, 'lines'> | undefined;
  if (!head) return null;
  const lines = getDb()
    .prepare(
      `SELECT l.medicine_id AS medicineId, l.name, l.quantity, l.unit_price AS unitPrice,
              l.quantity * l.unit_price AS lineTotal,
              COALESCE(m.stock, 0) AS availability, COALESCE(m.store_area, '') AS storeArea
         FROM dispense_lines l LEFT JOIN medicines m ON m.id = l.medicine_id
        WHERE l.token = ?`,
    )
    .all(token) as unknown as DispenseLine[];
  return { ...head, lines };
}

export interface DispenseSummary {
  readonly token: number;
  readonly prescriptionId: string;
  readonly total: number;
  readonly createdAt: string;
  readonly paid: boolean;
  readonly paidAt: string | null;
  /** Set when the counter closed the token as not collected (A1). */
  readonly abandonedAt: string | null;
  readonly abandonedReason: string | null;
  readonly lines: readonly DispenseLine[];
}

/** The seller dashboard's whole feed: newest first, unpaid and paid alike. */
export function listDispenses(limit = 50): DispenseSummary[] {
  const handle = getDb();
  const heads = handle
    .prepare(
      `SELECT token, prescription_id AS prescriptionId, total, created_at AS createdAt,
              paid, paid_at AS paidAt, abandoned_at AS abandonedAt,
              abandoned_reason AS abandonedReason
         FROM dispenses ORDER BY token DESC LIMIT ?`,
    )
    .all(limit) as Array<Omit<DispenseSummary, 'lines' | 'paid'> & { paid: number }>;

  // Joined, not stored: availability is what is on the shelf NOW, and a copy
  // frozen at dispense time would show the counter a stale figure.
  const linesFor = handle.prepare(
    `SELECT l.medicine_id AS medicineId, l.name, l.quantity, l.unit_price AS unitPrice,
            l.quantity * l.unit_price AS lineTotal,
            COALESCE(m.stock, 0) AS availability, COALESCE(m.store_area, '') AS storeArea
       FROM dispense_lines l LEFT JOIN medicines m ON m.id = l.medicine_id
      WHERE l.token = ?`,
  );

  return heads.map((head) => ({
    ...head,
    paid: head.paid === 1,
    lines: linesFor.all(head.token) as unknown as DispenseLine[],
  }));
}

/**
 * Mark a token paid, ONCE.
 *
 * The `paid = 0` guard is the whole point: a second press must not move the
 * timestamp or double-count the revenue, and doing it in the WHERE clause means
 * two taps racing cannot both win.
 */
export function markPaid(token: number): boolean {
  const info = getDb()
    .prepare('UPDATE dispenses SET paid = 1, paid_at = ? WHERE token = ? AND paid = 0')
    .run(new Date().toISOString(), token);
  return Number(info.changes) > 0;
}

/**
 * Change how much of one line is being handed over.
 *
 * STOCK MOVES BY THE DELTA, not by the new figure: if the counter drops 10 to 8
 * the shelf gains 2 back, and if it raises 8 to 12 the shelf loses 4. Setting
 * stock to the new quantity would silently undo the original dispense.
 *
 * Refused when the shelf cannot cover an increase. A counter that could take
 * stock negative would print a slip for medicine that is not there.
 */
export function updateLineQuantity(params: {
  token: number;
  medicineId: number;
  quantity: number;
}): { ok: true } | { ok: false; reason: string } {
  const handle = getDb();
  const line = handle
    .prepare('SELECT quantity, unit_price AS unitPrice FROM dispense_lines WHERE token = ? AND medicine_id = ?')
    .get(params.token, params.medicineId) as { quantity: number; unitPrice: number } | undefined;
  if (!line) return { ok: false, reason: 'That line is not on this token' };
  if (params.quantity <= 0) return { ok: false, reason: 'Quantity must be at least one' };

  const delta = params.quantity - line.quantity;
  if (delta > 0) {
    const stock = handle.prepare('SELECT stock FROM medicines WHERE id = ?').get(params.medicineId) as
      | { stock: number }
      | undefined;
    if (!stock || stock.stock < delta) {
      return { ok: false, reason: `Only ${stock?.stock ?? 0} left on the shelf` };
    }
  }

  handle.exec('BEGIN');
  try {
    handle
      .prepare('UPDATE dispense_lines SET quantity = ? WHERE token = ? AND medicine_id = ?')
      .run(params.quantity, params.token, params.medicineId);
    handle.prepare('UPDATE medicines SET stock = stock - ? WHERE id = ?').run(delta, params.medicineId);
    handle
      .prepare(
        `UPDATE dispenses SET total = (
           SELECT COALESCE(SUM(quantity * unit_price), 0) FROM dispense_lines WHERE token = ?
         ) WHERE token = ?`,
      )
      .run(params.token, params.token);
    handle.exec('COMMIT');
    return { ok: true };
  } catch (error) {
    handle.exec('ROLLBACK');
    throw error;
  }
}

export interface AdminStats {
  readonly totalSales: number;
  readonly totalRevenue: number;
  readonly medicinesInStock: number;
  readonly lowStock: readonly Medicine[];
}

/** The admin dashboard's whole job: what sold, what it earned, what is running out. */
export function adminStats(): AdminStats {
  const handle = getDb();
  const sales = handle.prepare('SELECT COUNT(*) AS n FROM dispenses').get() as { n: number };
  // Revenue counts PAID tokens only: a slip that was never settled is not income.
  const revenue = handle
    .prepare('SELECT COALESCE(SUM(total), 0) AS r FROM dispenses WHERE paid = 1')
    .get() as { r: number };
  const inStock = handle.prepare('SELECT COUNT(*) AS n FROM medicines WHERE stock > 0').get() as { n: number };
  const lowStock = handle
    .prepare(
      'SELECT id, name, strength, form, unit_price AS unitPrice, stock, store_area AS storeArea FROM medicines WHERE stock < 60 ORDER BY stock ASC LIMIT 10',
    )
    .all() as unknown as Medicine[];
  return {
    totalSales: sales.n,
    totalRevenue: revenue.r,
    medicinesInStock: inStock.n,
    lowStock,
  };
}
