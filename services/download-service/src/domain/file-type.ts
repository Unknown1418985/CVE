import type { DetectedFileType, DownloadRiskIndicator } from '@cve/contracts';

/** Bytes of the head of the content kept for type detection. */
export const SNIFF_BYTES = 4_096;

const startsWith = (head: Buffer, bytes: readonly number[], offset = 0) =>
  head.length >= offset + bytes.length && bytes.every((byte, index) => head[offset + index] === byte);

/** True when the bytes look like text (UTF-8 without NUL and with few control characters). */
function looksLikeText(head: Buffer): boolean {
  if (head.length === 0) return false;
  let control = 0;
  for (const byte of head) {
    if (byte === 0) return false;
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20 && byte !== 0x1b)) control += 1;
  }
  if (control / head.length > 0.02) return false;
  // Reject invalid UTF-8 except a sequence cut at the end of the sample.
  const decoded = new TextDecoder('utf-8', { fatal: false }).decode(head.subarray(0, head.length - 3));
  return !decoded.includes('�');
}

/**
 * Recognises the content type from its magic bytes. The declared Content-Type and the file name
 * are controlled by the source and are never trusted for this.
 */
export function detectFileType(head: Buffer, totalBytes: number): DetectedFileType {
  if (totalBytes === 0 || head.length === 0) return 'empty';
  if (startsWith(head, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(head, [0x50, 0x4b, 0x03, 0x04]) || startsWith(head, [0x50, 0x4b, 0x05, 0x06]))
    return 'zip';
  if (startsWith(head, [0x42, 0x5a, 0x68])) return 'bzip2';
  if (startsWith(head, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return 'xz';
  if (startsWith(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(head, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return 'rar';
  if (startsWith(head, [0x75, 0x73, 0x74, 0x61, 0x72], 257)) return 'tar';
  if (startsWith(head, [0x4d, 0x5a])) return 'pe-executable';
  if (startsWith(head, [0x7f, 0x45, 0x4c, 0x46])) return 'elf-executable';
  if (
    startsWith(head, [0xfe, 0xed, 0xfa, 0xce]) ||
    startsWith(head, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(head, [0xce, 0xfa, 0xed, 0xfe]) ||
    startsWith(head, [0xcf, 0xfa, 0xed, 0xfe])
  )
    return 'mach-o-executable';
  // 0xCAFEBABE is shared by Java classes and universal Mach-O; the next field disambiguates.
  if (startsWith(head, [0xca, 0xfe, 0xba, 0xbe])) {
    const major = head.length >= 8 ? head.readUInt16BE(6) : 0;
    return major >= 45 ? 'java-class' : 'mach-o-executable';
  }
  if (startsWith(head, [0x25, 0x50, 0x44, 0x46, 0x2d])) return 'pdf';
  if (startsWith(head, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return 'ole-document';
  if (startsWith(head, [0x23, 0x21])) return 'script';
  return looksLikeText(head) ? 'text' : 'binary';
}

export const FILE_TYPE_MIME: Readonly<Record<DetectedFileType, string>> = {
  gzip: 'application/gzip',
  zip: 'application/zip',
  tar: 'application/x-tar',
  bzip2: 'application/x-bzip2',
  xz: 'application/x-xz',
  '7z': 'application/x-7z-compressed',
  rar: 'application/vnd.rar',
  'pe-executable': 'application/vnd.microsoft.portable-executable',
  'elf-executable': 'application/x-elf',
  'mach-o-executable': 'application/x-mach-binary',
  'java-class': 'application/java-vm',
  pdf: 'application/pdf',
  'ole-document': 'application/x-ole-storage',
  script: 'text/x-script',
  text: 'text/plain',
  binary: 'application/octet-stream',
  empty: 'application/x-empty',
};

/** Extension of the generated download name (never the source's name). */
export const FILE_TYPE_EXTENSION: Readonly<Record<DetectedFileType, string>> = {
  gzip: '.gz',
  zip: '.zip',
  tar: '.tar',
  bzip2: '.bz2',
  xz: '.xz',
  '7z': '.7z',
  rar: '.rar',
  'pe-executable': '.bin',
  'elf-executable': '.bin',
  'mach-o-executable': '.bin',
  'java-class': '.bin',
  pdf: '.pdf',
  'ole-document': '.bin',
  script: '.txt',
  text: '.txt',
  binary: '.bin',
  empty: '.bin',
};

const ARCHIVES = new Set<DetectedFileType>(['gzip', 'zip', 'tar', 'bzip2', 'xz', '7z', 'rar']);
const EXECUTABLES = new Set<DetectedFileType>([
  'pe-executable',
  'elf-executable',
  'mach-o-executable',
  'java-class',
]);

/** Declared types that are consistent with a detected type (anything else is a mismatch). */
const CONSISTENT_DECLARATIONS: Readonly<Partial<Record<DetectedFileType, readonly string[]>>> = {
  gzip: ['application/gzip', 'application/x-gzip', 'application/x-tar'],
  zip: ['application/zip', 'application/x-zip-compressed'],
  text: ['text/plain', 'text/x-c', 'text/x-python', 'text/x-script', 'text/html'],
  script: ['text/plain', 'text/x-script', 'text/x-shellscript', 'text/x-python'],
  pdf: ['application/pdf'],
};

/** Media type without parameters, lower-case (`text/plain; charset=utf-8` → `text/plain`). */
export function essence(contentType: string | null): string | null {
  if (contentType === null) return null;
  const value = contentType.split(';')[0]?.trim().toLowerCase() ?? '';
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(value) ? value : null;
}

export function riskIndicators(
  detected: DetectedFileType,
  declaredContentType: string | null,
): DownloadRiskIndicator[] {
  const indicators: DownloadRiskIndicator[] = [];
  if (ARCHIVES.has(detected)) indicators.push('archive');
  if (EXECUTABLES.has(detected)) indicators.push('executable');
  if (detected === 'script') indicators.push('script');
  if (detected === 'ole-document') indicators.push('macro-capable-document');
  const declared = essence(declaredContentType);
  const consistent = CONSISTENT_DECLARATIONS[detected];
  if (
    declared !== null &&
    declared !== 'application/octet-stream' &&
    consistent !== undefined &&
    !consistent.includes(declared)
  ) {
    indicators.push('content-type-mismatch');
  }
  return indicators;
}
