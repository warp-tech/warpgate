import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tsconfigPaths from 'vite-tsconfig-paths'
import * as checker from 'vite-plugin-checker/lib/main.js'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [
        svelte(),
        tsconfigPaths(),
        (checker.default.default)({ typescript: true }),
    ],
    build: {
        sourcemap: true,
        manifest: true,
        commonjsOptions: {
            include: [
                'api-client/dist/*.js',
                '**/*.js',
            ],
            transformMixedEsModules: true,
        },
        rollupOptions: {
            input: {
                admin: 'src/admin/index.html',
                gateway: 'src/gateway/index.html',
                embed: 'src/main.embed.ts',
            },
        },
    },
})
