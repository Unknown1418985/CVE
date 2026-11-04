/**
 * Live tests run in one of two modes:
 * - default: the stack started with compose.dev.yaml (data store ports on 127.0.0.1);
 * - INFRA_TEST_FULL_STACK=true: `--profile apps --profile observability` without the dev
 *   override, where only Nginx and Grafana are reachable from the host.
 */
export const fullStack = process.env['INFRA_TEST_FULL_STACK'] === 'true';
export const devPorts = !fullStack;
