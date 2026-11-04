import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  booleanStringSchema,
  commaSeparatedListSchema,
  EnvValidationError,
  loadEnv,
  serviceEnvSchema,
} from './index.js';

const validServiceEnv = {
  DATABASE_URL: 'postgresql://svc:secret-password@localhost:5432/svc',
  REDIS_URL: 'redis://localhost:6379',
  RABBITMQ_URL: 'amqp://guest:guest@localhost:5672',
};

describe('loadEnv', () => {
  it('applies defaults for a backend service', () => {
    const env = loadEnv(serviceEnvSchema(4002), validServiceEnv);
    expect(env.PORT).toBe(4002);
    expect(env.NODE_ENV).toBe('development');
    expect(env.LOG_LEVEL).toBe('info');
    expect(env.SWAGGER_ENABLED).toBe(false);
    expect(env.CORS_ALLOWED_ORIGINS).toEqual([]);
  });

  it('treats empty strings as unset', () => {
    const env = loadEnv(serviceEnvSchema(4002), { ...validServiceEnv, PORT: '' });
    expect(env.PORT).toBe(4002);
  });

  it('reports every invalid variable without leaking values', () => {
    const attempt = () =>
      loadEnv(serviceEnvSchema(4002), {
        DATABASE_URL: 'mysql://user:top-secret@db/x',
        PORT: '99999',
      });
    expect(attempt).toThrow(EnvValidationError);
    try {
      attempt();
    } catch (error) {
      const envError = error as EnvValidationError;
      const variables = envError.issues.map((issue) => issue.variable);
      expect(variables).toEqual(
        expect.arrayContaining(['DATABASE_URL', 'PORT', 'REDIS_URL', 'RABBITMQ_URL']),
      );
      expect(envError.message).not.toContain('top-secret');
    }
  });

  it('works with custom schemas', () => {
    const schema = z.object({ FEATURE: booleanStringSchema });
    expect(loadEnv(schema, { FEATURE: '1' })).toEqual({ FEATURE: true });
    expect(() => loadEnv(schema, { FEATURE: 'yes' })).toThrow(EnvValidationError);
  });
});

describe('commaSeparatedListSchema', () => {
  it('trims and drops empty entries', () => {
    expect(commaSeparatedListSchema.parse(' https://a.test, ,https://b.test ')).toEqual([
      'https://a.test',
      'https://b.test',
    ]);
  });
});
