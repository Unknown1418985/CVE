import type { PrismaClient, UserProfile } from '../generated/prisma/client.js';
import type { ProfilePatch, ProfileRepository, StoredProfile } from './ports.js';

function toStored(row: UserProfile): StoredProfile {
  return {
    keycloakUserId: row.keycloakUserId,
    username: row.username,
    email: row.email,
    displayName: row.displayName,
    jobTitle: row.jobTitle,
    timezone: row.timezone,
    firstSeenAt: row.firstSeenAt,
    lastSeenAt: row.lastSeenAt,
  };
}

export class PrismaProfileRepository implements ProfileRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async touch(
    user: { id: string; username: string; email: string | null },
    at: Date,
  ): Promise<StoredProfile> {
    const row = await this.prisma.userProfile.upsert({
      where: { keycloakUserId: user.id },
      create: {
        keycloakUserId: user.id,
        username: user.username,
        email: user.email,
        firstSeenAt: at,
        lastSeenAt: at,
      },
      update: { username: user.username, email: user.email, lastSeenAt: at },
    });
    return toStored(row);
  }

  async update(userId: string, patch: ProfilePatch): Promise<StoredProfile> {
    const row = await this.prisma.userProfile.update({
      where: { keycloakUserId: userId },
      data: {
        ...(patch.displayName === undefined ? {} : { displayName: patch.displayName }),
        ...(patch.jobTitle === undefined ? {} : { jobTitle: patch.jobTitle }),
        ...(patch.timezone === undefined ? {} : { timezone: patch.timezone }),
      },
    });
    return toStored(row);
  }
}
