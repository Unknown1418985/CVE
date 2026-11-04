import swc from 'unplugin-swc';
import type { ViteUserConfig } from 'vitest/config';

export interface NodeVitestConfigOptions {
  /** Enable SWC so NestJS decorator metadata is emitted (esbuild does not emit it). */
  readonly decorators?: boolean;
  readonly include?: string[];
}

/** Shared Vitest preset for Node packages and NestJS services. */
export function createNodeVitestConfig(options: NodeVitestConfigOptions = {}): ViteUserConfig {
  return {
    plugins: options.decorators
      ? [
          swc.vite({
            module: { type: 'es6' },
            jsc: {
              target: 'es2022',
              parser: { syntax: 'typescript', decorators: true },
              transform: { legacyDecorator: true, decoratorMetadata: true },
              keepClassNames: true,
            },
          }),
        ]
      : [],
    test: {
      environment: 'node',
      include: options.include ?? ['src/**/*.test.ts', 'test/**/*.test.ts'],
      restoreMocks: true,
      passWithNoTests: false,
    },
  };
}
