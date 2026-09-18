import { mount } from 'svelte'
import '../theme'
import App from './AppNew.svelte'

/**
 * The redesigned admin UI is now the only one.
 *
 * `VITE_NEW_UI` is gone rather than defaulted to true: a flag that nobody can
 * turn off is not a rollback mechanism, it is a branch that never runs and
 * rots. Rolling back is `git revert` of the flip commit, which is honest about
 * what it costs.
 */
mount(App, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})
