import { mount } from 'svelte'
import '../theme'
import App from './App.svelte'

mount(App, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})
