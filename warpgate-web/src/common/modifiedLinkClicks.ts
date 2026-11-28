// use:link cancels click events independently of modifier, undo it
window.addEventListener(
    'click',
    e => {
        if (
            (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) &&
            (e.target as Element | null)?.closest?.('a[href^="#/"]')
        ) {
            e.stopPropagation()
        }
    },
    true,
)
