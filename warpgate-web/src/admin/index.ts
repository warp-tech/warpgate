import { mount } from 'svelte'
import '../theme'

/*
 * The flag test is written inline rather than imported from src/flags.ts.
 *
 * Vite replaces `import.meta.env.VITE_NEW_UI` with a literal wherever it
 * appears, but Rollup will only eliminate the dead dynamic import if the
 * condition is a literal *in this module*. Importing a `const NEW_UI` from
 * another module defeats that: both branches survive and the bundle carries
 * both shells, which was measurable — 111 KB of the other UI riding along.
 */
const App =
    import.meta.env.VITE_NEW_UI === 'true'
        ? (await import('./AppNew.svelte')).default
        : (await import('./App.svelte')).default

mount(App, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})
