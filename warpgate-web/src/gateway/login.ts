import { mount } from 'svelte'
import Login from './Login.svelte'

const app = {}
mount(Login, {
    // biome-ignore lint/style/noNonNullAssertion: x
    target: document.getElementById('app')!,
})

export default app
