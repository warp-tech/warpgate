import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tsconfigPaths from 'vite-tsconfig-paths'
import { checker } from 'vite-plugin-checker'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [
        svelte(),
        tsconfigPaths(),
        checker({ typescript: true }),
    ],
    base: '/@warpgate',
    build: {
        sourcemap: true,
        manifest: true,
        commonjsOptions: {
            include: [
                'src/gateway/lib/api-client/dist/*.js',
                'src/admin/lib/api-client/dist/*.js',
                '**/*.js',
            ],
            transformMixedEsModules: true,
        },
        rollupOptions: {
            input: {
                admin: 'src/admin/index.html',
                gateway: 'src/gateway/index.html',
                embed: 'src/embed/index.ts',
            },
        },
    },
})
