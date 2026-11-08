const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Route parameters that name a resource by UUID are checked before any request is made. */
export function isUuid(value: string): boolean {
  return UUID.test(value);
}
