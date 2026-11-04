import type { PrismaClient } from '../generated/prisma/client.js';
import type { SyncCursorRepository } from './ports.js';

export class PrismaSyncCursorRepository implements SyncCursorRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async get(name: string): Promise<Date | null> {
    const row = await this.prisma.syncCursor.findUnique({ where: { name } });
    return row === null ? null : new Date(Number(row.position));
  }

  async set(name: string, position: Date): Promise<void> {
    const value = BigInt(position.getTime());
    await this.prisma.syncCursor.upsert({
      where: { name },
      create: { name, position: value },
      update: { position: value },
    });
  }
}
