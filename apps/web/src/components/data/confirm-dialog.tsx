'use client';

import { Loader2 } from 'lucide-react';
import { useId, useState, type ReactElement, type ReactNode } from 'react';

import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { describeError } from '@/lib/api/client';

/**
 * Confirmation for sensitive actions (CLAUDE.md §9). With `reasonLabel` the user must give a
 * reason, which the services record in the audit trail.
 */
export function ConfirmDialog({
  trigger,
  title,
  description,
  confirmLabel,
  destructive = false,
  reasonLabel,
  reasonRequired = true,
  onConfirm,
}: {
  trigger: ReactNode;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  reasonLabel?: string;
  reasonRequired?: boolean;
  onConfirm: (reason: string) => Promise<unknown>;
}): ReactElement {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reasonId = useId();
  const needsReason = reasonLabel !== undefined && reasonRequired;
  const disabled = pending || (needsReason && reason.trim().length === 0);

  const confirm = async (): Promise<void> => {
    setPending(true);
    setError(null);
    try {
      await onConfirm(reason.trim());
      setOpen(false);
      setReason('');
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setPending(false);
    }
  };

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setError(null);
      }}
    >
      <AlertDialogTrigger asChild>{trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription asChild>
            <div>{description}</div>
          </AlertDialogDescription>
        </AlertDialogHeader>
        {reasonLabel === undefined ? null : (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor={reasonId}>
              {reasonLabel}
              {needsReason ? ' (required)' : ' (optional)'}
            </Label>
            <Textarea
              id={reasonId}
              value={reason}
              maxLength={2000}
              onChange={(event) => {
                setReason(event.target.value);
              }}
            />
          </div>
        )}
        {error === null ? null : (
          <p role="alert" className="text-sm text-status-down">
            {error}
          </p>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>Cancel</AlertDialogCancel>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            disabled={disabled}
            onClick={() => {
              void confirm();
            }}
          >
            {pending ? <Loader2 className="animate-spin" aria-hidden="true" /> : null}
            {confirmLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
