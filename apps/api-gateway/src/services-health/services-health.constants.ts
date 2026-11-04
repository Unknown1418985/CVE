export const SERVICE_REGISTRY = Symbol('SERVICE_REGISTRY');
export const HTTP_FETCH = Symbol('HTTP_FETCH');
export const SERVICES_HEALTH_TIMEOUT_MS = Symbol('SERVICES_HEALTH_TIMEOUT_MS');

export type HttpFetch = typeof fetch;
