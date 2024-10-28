import { mount } from 'svelte'
import '../theme'
import App from './App.svelte'

mount(App, {
    target: document.getElementById('app')!,
})

export { }
