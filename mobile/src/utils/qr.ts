/**
 * QR codes without a native module.
 *
 * WHY THIS EXISTS INSTEAD OF react-native-qrcode-svg. Rendering a QR needs two
 * things: a module matrix (pure JavaScript — `qrcode`) and a way to put pixels
 * on screen. The usual answer pulls in react-native-svg, a NATIVE dependency
 * that requires a new development build. This wallet's dev build is frozen
 * until the owner approves the next one (see the local-DB round), so the pixels
 * are produced here instead: the matrix is written into a minimal PNG and shown
 * through RN's own <Image>, which accepts a base64 data URI. No native module,
 * no rebuild.
 *
 * The PNG is intentionally the simplest valid one — 8-bit greyscale with zlib
 * "stored" blocks (no compression). A QR image is small (tens of KB at most),
 * and correctness under a phone camera matters more than bytes saved.
 *
 * THIS FILE MUST NOT IMPORT REACT NATIVE, so the exact same code can be run
 * under Node and its output decoded by a real QR reader as a test (see
 * tools/verifyQrRender.mjs). The renderer is only trustworthy if it has been
 * scanned, not merely looked at.
 */
import QRCode from 'qrcode';

/** CRC-32 (PNG's polynomial), computed once. */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array<ArrayBufferLike>): number {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i += 1) {
    c = CRC_TABLE[(c ^ bytes[i]!) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function adler32(bytes: Uint8Array<ArrayBufferLike>): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    a = (a + bytes[i]!) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

const u32be = (value: number): Uint8Array =>
  new Uint8Array([(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]);

/** zlib wrapper around stored (uncompressed) deflate blocks. */
function zlibStored(payload: Uint8Array<ArrayBufferLike>): Uint8Array {
  const header = new Uint8Array([0x78, 0x01]);
  const blocks: Uint8Array<ArrayBufferLike>[] = [];
  const MAX = 65535;
  for (let offset = 0; offset < payload.length || payload.length === 0; offset += MAX) {
    const end = Math.min(offset + MAX, payload.length);
    const len = end - offset;
    const final = end >= payload.length ? 1 : 0;
    const block = new Uint8Array(5 + len);
    block[0] = final; // BFINAL, BTYPE=00 (stored)
    block[1] = len & 0xff;
    block[2] = (len >>> 8) & 0xff;
    block[3] = ~len & 0xff;
    block[4] = (~len >>> 8) & 0xff;
    block.set(payload.subarray(offset, end), 5);
    blocks.push(block);
    if (payload.length === 0) break;
  }
  const total = header.length + blocks.reduce((sum, b) => sum + b.length, 0) + 4;
  const out = new Uint8Array(total);
  let cursor = 0;
  out.set(header, cursor);
  cursor += header.length;
  for (const block of blocks) {
    out.set(block, cursor);
    cursor += block.length;
  }
  out.set(u32be(adler32(payload)), cursor);
  return out;
}

function pngChunk(type: string, data: Uint8Array<ArrayBufferLike>): Uint8Array {
  const typeBytes = new TextEncoder().encode(type);
  const body = new Uint8Array(typeBytes.length + data.length);
  body.set(typeBytes, 0);
  body.set(data, typeBytes.length);
  const out = new Uint8Array(4 + body.length + 4);
  // The length field counts the DATA only — not the 4-byte type that precedes
  // it. Counting both wrote `17` for IHDR's 13 bytes and every PNG reader
  // rejected the file (libpng: "IHDR: invalid").
  out.set(u32be(data.length), 0);
  out.set(body, 4);
  out.set(u32be(crc32(body)), 4 + body.length);
  return out;
}

/** RFC 4648 base64. `btoa` is absent from RN 0.83's polyfills (steno #376). */
export function bytesToBase64(bytes: Uint8Array<ArrayBufferLike>): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += chars[b0 >> 2];
    out += chars[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? '=' : chars[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? '=' : chars[b2 & 0x3f];
  }
  return out;
}

export interface QrImageOptions {
  /** Pixels per QR module. Higher scans from further away; 6–8 is right on a phone. */
  scale?: number;
  /** Quiet zone in modules. The spec requires 4; keep it. */
  quietZone?: number;
  errorCorrectionLevel?: 'L' | 'M' | 'Q' | 'H';
}

/**
 * Encode `text` as a QR and return a PNG data URI for <Image source={{uri}} />.
 *
 * Throws when the text does not fit a QR at the requested correction level
 * rather than silently emitting a smaller, unreadable one: an oversized payload
 * is a real failure (a presentation that will not fit) and must be visible.
 */
export function qrPngDataUri(text: string, options: QrImageOptions = {}): string {
  const scale = options.scale ?? 6;
  const quietZone = options.quietZone ?? 4;
  const qr = QRCode.create(text, { errorCorrectionLevel: options.errorCorrectionLevel ?? 'M' });
  const moduleCount = qr.modules.size;
  const matrix = qr.modules.data;

  const size = (moduleCount + quietZone * 2) * scale;
  const stride = size;
  // Greyscale, one byte per pixel. Filter byte 0 per scanline, as PNG requires.
  const raw = new Uint8Array(size * (stride + 1));
  for (let y = 0; y < size; y += 1) {
    const rowStart = y * (stride + 1);
    raw[rowStart] = 0;
    const moduleY = Math.floor(y / scale) - quietZone;
    for (let x = 0; x < size; x += 1) {
      const moduleX = Math.floor(x / scale) - quietZone;
      const dark =
        moduleY >= 0 &&
        moduleX >= 0 &&
        moduleY < moduleCount &&
        moduleX < moduleCount &&
        matrix[moduleY * moduleCount + moduleX] === 1;
      raw[rowStart + 1 + x] = dark ? 0 : 255;
    }
  }

  const ihdr = new Uint8Array(13);
  ihdr.set(u32be(size), 0); // width
  ihdr.set(u32be(size), 4); // height
  ihdr[8] = 8; // bit depth
  ihdr[9] = 0; // colour type: greyscale
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const chunks: Uint8Array<ArrayBufferLike>[] = [
    new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  ];
  chunks.push(pngChunk('IHDR', ihdr));
  chunks.push(pngChunk('IDAT', zlibStored(raw)));
  chunks.push(pngChunk('IEND', new Uint8Array(0)));

  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const png = new Uint8Array(total);
  let cursor = 0;
  for (const chunk of chunks) {
    png.set(chunk, cursor);
    cursor += chunk.length;
  }

  return `data:image/png;base64,${bytesToBase64(png)}`;
}
