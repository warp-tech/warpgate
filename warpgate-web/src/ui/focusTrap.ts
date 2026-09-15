/**
 * Focus management for modal surfaces (Modal, Drawer).
 *
 * Does the four things a dialog owes the keyboard:
 *   1. moves focus in on open, preferring an element marked data-autofocus,
 *      else the first tabbable thing, else the container itself
 *   2. keeps Tab and Shift+Tab inside
 *   3. restores focus to whatever opened it on close — the single most
 *      commonly skipped step, and the one that strands keyboard users at the
 *      top of the document
 *   4. marks the rest of the page inert so a screen reader's virtual cursor
 *      cannot wander out of the dialog
 */

const TABBABLE = [
    'a[href]',
    'button:not(:disabled)',
    'input:not(:disabled):not([type="hidden"])',
    'select:not(:disabled)',
    'textarea:not(:disabled)',
    '[tabindex]:not([tabindex="-1"])',
].join(',')

function tabbable(container: HTMLElement): HTMLElement[] {
    return Array.from(container.querySelectorAll<HTMLElement>(TABBABLE)).filter(
        el =>
            !el.hasAttribute('inert') &&
            el.offsetWidth + el.offsetHeight > 0 &&
            getComputedStyle(el).visibility !== 'hidden',
    )
}

/**
 * Everything outside the dialog, expressed as the siblings of each ancestor on
 * the path from the dialog up to <body>.
 *
 * Marking `document.body.children` instead only works when the dialog is a
 * direct child of body. These dialogs render inline at their component's
 * position in the tree — inside #app — so that approach marks the dialog's own
 * ancestor inert, which makes the dialog inert too and silently prevents focus
 * from ever entering it. Walking the ancestor chain marks the true complement.
 */
function outsideOf(node: HTMLElement): HTMLElement[] {
    const out: HTMLElement[] = []
    let current: HTMLElement | null = node
    while (current && current !== document.body) {
        const parent: HTMLElement | null = current.parentElement
        if (!parent) {
            break
        }
        for (const sibling of Array.from(parent.children)) {
            if (
                sibling === current ||
                sibling.hasAttribute('inert') ||
                // The scrim is part of the overlay, not the page behind it.
                // `inert` also removes an element from hit-testing, so marking
                // it would silently kill click-outside-to-close.
                sibling.hasAttribute('data-wg-overlay')
            ) {
                continue
            }
            out.push(sibling as HTMLElement)
        }
        current = parent
    }
    return out
}

export function focusTrap(node: HTMLElement) {
    const previouslyFocused = document.activeElement as HTMLElement | null

    const siblings = outsideOf(node)
    for (const el of siblings) {
        el.setAttribute('inert', '')
    }

    function moveFocusIn() {
        const preferred = node.querySelector<HTMLElement>('[data-autofocus]')
        const target = preferred ?? tabbable(node)[0] ?? node
        if (target === node && !node.hasAttribute('tabindex')) {
            node.setAttribute('tabindex', '-1')
        }
        target.focus()
    }

    function onKeydown(event: KeyboardEvent) {
        if (event.key !== 'Tab') {
            return
        }
        const items = tabbable(node)
        if (!items.length) {
            event.preventDefault()
            return
        }
        const first = items[0]
        const last = items[items.length - 1]
        const active = document.activeElement

        if (event.shiftKey && (active === first || active === node)) {
            event.preventDefault()
            last?.focus()
        } else if (!event.shiftKey && active === last) {
            event.preventDefault()
            first?.focus()
        }
    }

    // Deferred a frame: on open the node may not be laid out yet, and
    // tabbable() filters on offsetWidth/offsetHeight.
    const raf = requestAnimationFrame(moveFocusIn)
    node.addEventListener('keydown', onKeydown)

    return {
        destroy() {
            cancelAnimationFrame(raf)
            node.removeEventListener('keydown', onKeydown)
            for (const el of siblings) {
                el.removeAttribute('inert')
            }
            // Guard against restoring to something that has since been removed
            if (previouslyFocused?.isConnected) {
                previouslyFocused.focus()
            }
        },
    }
}

/** Locks body scroll while an overlay is open, preserving the scrollbar gutter. */
export function scrollLock() {
    const { overflow, paddingRight } = document.body.style
    const gap = window.innerWidth - document.documentElement.clientWidth
    document.body.style.overflow = 'hidden'
    if (gap > 0) {
        document.body.style.paddingRight = `${gap}px`
    }
    return {
        release() {
            document.body.style.overflow = overflow
            document.body.style.paddingRight = paddingRight
        },
    }
}
