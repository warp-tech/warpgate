import sveltePreprocess from 'svelte-preprocess'

export default {
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
