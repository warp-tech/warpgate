import { mount } from 'svelte'
import '../theme'
import Root from './Root.svelte'

mount(Root, {
    target: document.getElementById('app')!,
})

export { }
