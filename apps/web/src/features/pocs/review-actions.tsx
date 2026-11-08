'use client';

import type { PocAssociation } from '@cve/contracts';
import { Check, RotateCcw, X } from 'lucide-react';
import type { ReactElement } from 'react';

import { ConfirmDialog } from '@/components/data/confirm-dialog';
import { Button } from '@/components/ui/button';
import { useCan } from '@/features/auth/use-me';

import { useReviewAssociation } from './mutations';

export function ReviewActions({
  association,
}: {
  association: PocAssociation;
}): ReactElement | null {
  const can = useCan('poc:manage');
  const review = useReviewAssociation();
  if (can !== true) return null;
  const subject = `${association.repositoryFullName} ↔ ${association.cveId}`;
  return (
    <div className="flex flex-wrap gap-1">
      {association.reviewStatus !== 'confirmed' ? (
        <ConfirmDialog
          trigger={
            <Button size="sm" variant="outline">
              <Check aria-hidden="true" /> Confirm
            </Button>
          }
          title="Confirm association"
          description={
            <>
              Confirm that <strong>{subject}</strong> is a PoC for this CVE. Confirmation is
              recorded with your name.
            </>
          }
          confirmLabel="Confirm association"
          reasonLabel="Review note"
          reasonRequired={false}
          onConfirm={(note) =>
            review.mutateAsync({
              id: association.id,
              version: association.version,
              reviewStatus: 'confirmed',
              note,
            })
          }
        />
      ) : null}
      {association.reviewStatus !== 'rejected' ? (
        <ConfirmDialog
          trigger={
            <Button size="sm" variant="outline">
              <X aria-hidden="true" /> Reject
            </Button>
          }
          title="Reject association"
          description={
            <>
              Reject <strong>{subject}</strong>. A rejected association stays rejected when the
              repository is discovered again.
            </>
          }
          confirmLabel="Reject association"
          destructive
          reasonLabel="Reason"
          onConfirm={(note) =>
            review.mutateAsync({
              id: association.id,
              version: association.version,
              reviewStatus: 'rejected',
              note,
            })
          }
        />
      ) : null}
      {association.reviewStatus !== 'candidate' ? (
        <ConfirmDialog
          trigger={
            <Button size="sm" variant="ghost">
              <RotateCcw aria-hidden="true" /> Reopen
            </Button>
          }
          title="Reopen review"
          description={
            <>
              Set <strong>{subject}</strong> back to candidate.
            </>
          }
          confirmLabel="Reopen"
          reasonLabel="Reason"
          onConfirm={(note) =>
            review.mutateAsync({
              id: association.id,
              version: association.version,
              reviewStatus: 'candidate',
              note,
            })
          }
        />
      ) : null}
    </div>
  );
}
