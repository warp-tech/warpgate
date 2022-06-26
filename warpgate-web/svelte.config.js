import sveltePreprocess from 'svelte-preprocess'

/** @type {import('@sveltejs/kit').Config} */
const config = {
    compilerOptions: {
        enableSourcemap: true,
    },
    preprocess: sveltePreprocess({
        sourceMap: true,
    }),
    experimental: {
        prebundleSvelteLibraries: true,
    },
}

export default config
