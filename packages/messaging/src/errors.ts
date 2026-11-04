/**
 * Thrown by event handlers to signal that retrying cannot succeed (for example a
 * business-rule violation). The message is moved to the dead-letter queue immediately.
 */
export class NonRetryableEventError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'NonRetryableEventError';
  }
}

/** Raised when an event cannot be handed to the broker. */
export class EventPublishError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'EventPublishError';
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
