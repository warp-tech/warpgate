navigator.serviceWorker.getRegistrations().then(registrations => {
    for (let registration of registrations) {
        registration.unregister()
    }
})

console.log('Embedded!')

export { }
