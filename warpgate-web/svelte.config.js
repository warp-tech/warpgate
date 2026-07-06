import sveltePreprocess from 'svelte-preprocess'

/** @type {import('@sveltejs/kit').Config} */
const config = {
    compilerOptions: {
        dev: true,
    },
    preprocess: sveltePreprocess({
        sourceMap: false,
    }),
    vitePlugin: {
        prebundleSvelteLibraries: true,
    },
}

export default config
