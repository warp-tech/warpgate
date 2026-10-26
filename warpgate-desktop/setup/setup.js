const { invoke } = window.__TAURI__.core

const form = document.getElementById('form')
const input = document.getElementById('url')
const submit = document.getElementById('submit')
const error = document.getElementById('error')

invoke('current_server').then(url => {
    if (url) {
        input.value = url
        input.select()
    }
})

form.addEventListener('submit', async event => {
    event.preventDefault()
    error.hidden = true
    submit.disabled = true
    submit.textContent = 'Connecting…'
    try {
        await invoke('connect', { url: input.value })
    } catch (e) {
        error.textContent = String(e)
        error.hidden = false
        submit.disabled = false
        submit.textContent = 'Connect'
    }
})
