import sveltePreprocess from 'svelte-preprocess'

/** @type {import('@sveltejs/kit').Config} */
const config = {
    compilerOptions: {
        enableSourcemap: true,
        dev: true,
    },
    preprocess: sveltePreprocess({
        sourceMap: true,
    }),
    vitePlugin: {
        prebundleSvelteLibraries: true,
    },
}

export default config
