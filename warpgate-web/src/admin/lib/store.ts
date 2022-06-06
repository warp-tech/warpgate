import { writable } from 'svelte/store'

export const authenticatedUsername = writable<string|null>(null)
