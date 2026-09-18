import { mount } from 'svelte'
import '../theme'

/**
 * The portal had no VITE_NEW_UI gate — gateway/index.ts mounted Root
 * unconditionally, so migrating a portal screen would have changed the live
 * sign-in page with no way back. The flag is the rollback mechanism, so the
 * portal gets the same one the admin side has.
 *
 * The test must be written inline, exactly like admin/index.ts: Vite replaces
 * `import.meta.env.VITE_NEW_UI` with a literal, and Rollup only eliminates the
 * losing branch when the condition is a literal **in this module**. Importing
 * NEW_UI from flags.ts instead ships both shells — that was measured at
 * +111 KB on the admin side in Phase 1.
 */
const Root =
    import.meta.env.VITE_NEW_UI === 'true'
        ? (await import('./RootNew.svelte')).default
        : (await import('./Root.svelte')).default

mount(Root, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})
