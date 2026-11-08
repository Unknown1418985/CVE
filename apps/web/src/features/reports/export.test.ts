import { describe, expect, it } from 'vitest';

import { csvField, exportFileName, toCsv, toJson, type ExportColumn } from './export';

interface Row {
  id: string;
  score: number | null;
  tags: string[];
}

const columns: ExportColumn<Row>[] = [
  { header: 'ID', value: (row) => row.id },
  { header: 'Score', value: (row) => row.score },
  { header: 'Tags', value: (row) => row.tags },
];

describe('csvField', () => {
  it('quotes separators, quotes and line breaks', () => {
    expect(csvField('a,b')).toBe('"a,b"');
    expect(csvField('say "hi"')).toBe('"say ""hi"""');
    expect(csvField('line\nbreak')).toBe('"line\nbreak"');
    expect(csvField(' padded ')).toBe('" padded "');
  });

  it('neutralises spreadsheet formulas from external text', () => {
    expect(csvField('=HYPERLINK("http://x")')).toBe(`"'=HYPERLINK(""http://x"")"`);
    expect(csvField('+1')).toBe("'+1");
    expect(csvField('-cmd')).toBe("'-cmd");
    expect(csvField('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvField(['=1', 'b'])).toBe("'=1; b");
  });

  it('keeps numbers (including negatives) and empty values as they are', () => {
    expect(csvField(-1.5)).toBe('-1.5');
    expect(csvField(9.8)).toBe('9.8');
    expect(csvField(null)).toBe('');
    expect(csvField(undefined)).toBe('');
    expect(csvField(true)).toBe('true');
  });
});

describe('toCsv', () => {
  it('writes a header and one CRLF-terminated line per row with a UTF-8 BOM', () => {
    const csv = toCsv([{ id: 'CVE-2026-0001', score: 9.8, tags: ['a', 'b'] }], columns);
    expect(csv).toBe('﻿ID,Score,Tags\r\nCVE-2026-0001,9.8,a; b\r\n');
  });

  it('writes only the header for no rows', () => {
    expect(toCsv([], columns)).toBe('﻿ID,Score,Tags\r\n');
  });
});

describe('toJson', () => {
  it('keeps types and adds metadata', () => {
    const parsed = JSON.parse(
      toJson([{ id: 'x', score: null, tags: ['t'] }], columns, { report: 'Test' }),
    ) as unknown;
    expect(parsed).toEqual({
      report: 'Test',
      rowCount: 1,
      data: [{ ID: 'x', Score: null, Tags: ['t'] }],
    });
  });
});

describe('exportFileName', () => {
  it('builds a safe name with a UTC timestamp', () => {
    expect(exportFileName('Known Exploited / CVEs', 'csv', new Date('2026-11-08T10:20:30Z'))).toBe(
      'known-exploited-cves-2026-11-08-102030.csv',
    );
    expect(exportFileName('../../', 'json', new Date('2026-11-08T10:20:30Z'))).toBe(
      'report-2026-11-08-102030.json',
    );
  });
});
