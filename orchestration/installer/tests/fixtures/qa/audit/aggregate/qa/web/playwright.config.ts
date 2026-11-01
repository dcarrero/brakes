import { defineConfig } from '@playwright/test';

export default defineConfig({
  retries: 0,
  workers: 1,
  updateSnapshots: 'missing',
  use: { baseURL: process.env.QA_WEB_URL },
});
