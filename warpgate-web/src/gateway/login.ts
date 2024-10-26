import { mount } from 'svelte'
import Login from './Login.svelte'

const app = {}
mount(Login, {
    target: document.getElementById('app')!,
})

export default app
