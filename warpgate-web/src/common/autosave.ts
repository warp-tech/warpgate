import { BehaviorSubject } from 'rxjs'
import { get, writable, type Writable } from 'svelte/store'

export function autosave<T> (key: string, initial: T): ([Writable<T>, BehaviorSubject<T>]) {
    key = `warpgate:${key}`
    const v = writable(JSON.parse(localStorage.getItem(key) ?? JSON.stringify(initial)))
    const v$ = new BehaviorSubject<T>(get(v))
    v.subscribe(value => {
        localStorage.setItem(key, JSON.stringify(value))
        v$.next(value)
    })
    return [v, v$]
}
