import { mount } from 'svelte'
import '../theme'
import Root from './RootNew.svelte'

/**
 * The redesigned portal is now the only one. See admin/index.ts for why the
 * flag was removed rather than defaulted.
 */
mount(Root, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})
