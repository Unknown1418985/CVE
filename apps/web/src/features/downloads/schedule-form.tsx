'use client';

import { zodResolver } from '@hookform/resolvers/zod';
import { Plus } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { useState, type ReactElement } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';

import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { describeError } from '@/lib/api/client';

import { useScheduleDownload } from './mutations';

const CVE_ID = /^CVE-\d{4}-\d{4,19}$/;

export const scheduleFormSchema = z.object({
  url: z
    .string()
    .trim()
    .min(8, 'Enter the URL to download')
    .max(2048)
    .refine(
      (value) => /^https:\/\/[^\s]+$/i.test(value),
      'Only https URLs from an approved source are accepted',
    ),
  cveIds: z
    .string()
    .trim()
    .max(2000)
    .refine(
      (value) =>
        value === '' ||
        value
          .split(/[\s,]+/)
          .filter(Boolean)
          .every((id) => CVE_ID.test(id.toUpperCase())),
      'Separate CVE IDs with commas, e.g. CVE-2026-1234, CVE-2026-5678',
    ),
  priority: z.enum(['1', '3', '5', '7', '10']),
  scheduledFor: z
    .string()
    .refine(
      (value) => value === '' || !Number.isNaN(Date.parse(value)),
      'Enter a valid date and time',
    ),
  reason: z.string().trim().max(2000),
});
type FormValues = z.input<typeof scheduleFormSchema>;

/** Splits the CVE ID field into a deduplicated, upper-cased list. */
export function parseCveList(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\s,]+/)
        .filter(Boolean)
        .map((id) => id.toUpperCase()),
    ),
  ];
}

function FieldError({
  id,
  message,
}: {
  id: string;
  message: string | undefined;
}): ReactElement | null {
  return message === undefined ? null : (
    <p id={id} className="text-xs text-status-down">
      {message}
    </p>
  );
}

/**
 * Schedules a download from an approved source. The content is never opened: it is stored in
 * quarantine, scanned, and only an administrator can release it.
 */
export function ScheduleDownloadForm(): ReactElement {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const schedule = useScheduleDownload();
  const form = useForm<FormValues>({
    resolver: zodResolver(scheduleFormSchema),
    defaultValues: { url: '', cveIds: '', priority: '5', scheduledFor: '', reason: '' },
  });
  const errors = form.formState.errors;

  const submit = form.handleSubmit(async (values) => {
    setError(null);
    const parsed = scheduleFormSchema.parse(values);
    try {
      const result = await schedule.mutateAsync({
        url: parsed.url,
        cveIds: parseCveList(parsed.cveIds),
        priority: Number(parsed.priority),
        // datetime-local is the user's local time; the API expects UTC.
        scheduledFor:
          parsed.scheduledFor === '' ? null : new Date(parsed.scheduledFor).toISOString(),
        reason: parsed.reason,
      });
      form.reset();
      setOpen(false);
      router.push(`/downloads/requests/${result.data.request.id}`);
    } catch (caught) {
      setError(describeError(caught));
    }
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setError(null);
      }}
    >
      <DialogTrigger asChild>
        <Button>
          <Plus aria-hidden="true" /> Schedule download
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Schedule a download</DialogTitle>
          <DialogDescription>
            Only URLs recognised by an enabled download source are accepted (see the Sources tab).
            Every hop is checked against the source allowlist, private addresses are blocked, and
            the file is stored in quarantine. It is never executed or extracted.
          </DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            void submit(event);
          }}
          noValidate
        >
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="download-url">Source URL</Label>
            <Input
              id="download-url"
              type="url"
              inputMode="url"
              autoComplete="off"
              placeholder="https://github.com/owner/repo/tree/<commit>"
              aria-invalid={errors.url !== undefined}
              aria-describedby="download-url-error"
              {...form.register('url')}
            />
            <FieldError id="download-url-error" message={errors.url?.message} />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="download-cves">Related CVE IDs (optional)</Label>
            <Input
              id="download-cves"
              placeholder="CVE-2026-1234, CVE-2026-5678"
              aria-invalid={errors.cveIds !== undefined}
              aria-describedby="download-cves-error"
              {...form.register('cveIds')}
            />
            <FieldError id="download-cves-error" message={errors.cveIds?.message} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="download-priority">Priority</Label>
              <Select
                id="download-priority"
                {...form.register('priority')}
                options={[
                  { value: '1', label: '1 (highest)' },
                  { value: '3', label: '3' },
                  { value: '5', label: '5 (normal)' },
                  { value: '7', label: '7' },
                  { value: '10', label: '10 (lowest)' },
                ]}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="download-when">Not before (optional)</Label>
              <Input
                id="download-when"
                type="datetime-local"
                aria-invalid={errors.scheduledFor !== undefined}
                aria-describedby="download-when-error"
                {...form.register('scheduledFor')}
              />
              <FieldError id="download-when-error" message={errors.scheduledFor?.message} />
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="download-reason">Reason (optional)</Label>
            <Textarea id="download-reason" maxLength={2000} {...form.register('reason')} />
          </div>
          {error === null ? null : (
            <p role="alert" className="text-sm text-status-down">
              {error}
            </p>
          )}
          <DialogFooter>
            <Button type="submit" disabled={form.formState.isSubmitting}>
              Schedule download
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
