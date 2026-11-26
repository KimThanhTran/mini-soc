import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// In development the API is reached through the dev server, so the browser sees one origin and no CORS is needed.
export default defineConfig({
  plugins: [react()],
  server: { proxy: { '/api': process.env.API_TARGET || 'http://localhost:8000' } },
});
