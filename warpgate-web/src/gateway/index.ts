import { mount } from 'svelte'
import '../theme'
import Root from './Root.svelte'

mount(Root, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})
