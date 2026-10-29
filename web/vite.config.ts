import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// The build goes straight into the Go tree: internal/web embeds dist/.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  return {
    base: '/',
    plugins: [react()],
    build: {
      outDir: '../internal/web/dist',
      emptyOutDir: true,
      sourcemap: false,
      target: 'es2020',
    },
    server: {
      host: '127.0.0.1',
      // `npm run dev:live` talks to a running `nebctl web` (set NEBCTL_API
      // to its origin); the session cookie must be set on this origin first.
      proxy: { '/api': env.NEBCTL_API || 'http://127.0.0.1:8080' },
    },
  };
});
