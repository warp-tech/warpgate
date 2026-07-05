import sveltePreprocess from 'svelte-preprocess'

/** @type {import('@sveltejs/kit').Config} */
const config = {
    compilerOptions: {
        dev: true,
        compatibility: {
          componentApi: 4,
        },
    },
    preprocess: sveltePreprocess({
        sourceMap: false,
    }),
    vitePlugin: {
        prebundleSvelteLibraries: true,
    },
}

export default config
