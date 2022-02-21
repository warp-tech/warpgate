import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import tsconfigPaths from 'vite-tsconfig-paths'
import * as checker from 'vite-plugin-checker/lib/main.js'

console.log(checker)
// https://vitejs.dev/config/
export default defineConfig({
    plugins: [
        svelte(),
        tsconfigPaths(),
        (checker.default.default)({ typescript: true }),
    ],
    build: {
        sourcemap: true,
    },
})
