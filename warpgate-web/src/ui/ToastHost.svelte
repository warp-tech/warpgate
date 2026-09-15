<script lang="ts">
    import { STATUS } from './StatusMarker.svelte'
    /**
     * NET-NEW primitive (view half). Mounted once per app shell.
     *
     * Live-region choice: the container is `role="status"` / `aria-live="polite"`
     * so routine confirmations do not interrupt what the operator is reading,
     * while each error toast carries `role="alert"` (assertive) because a
     * failed action is exactly the case where interrupting is correct.
     */
    import { toasts } from './toasts.svelte'

    const TONE_TOKEN = {
        info: '--wg-primary',
        success: '--wg-tertiary',
        warning: '--wg-secondary',
        error: '--wg-error',
    } as const

    // Keep the marker geometry consistent with the status convention rather
    // than inventing a second vocabulary of icons.
    const TONE_SHAPE = {
        info: 'dot',
        success: 'ring',
        warning: 'diamond',
        error: 'triangle',
    } as const

    void STATUS

    function holdAll() {
        for (const t of toasts.items) {
            toasts.hold(t.id)
        }
    }

    function resumeAll() {
        for (const t of toasts.items) {
            toasts.resume(t.id)
        }
    }
</script>

{#if toasts.items.length}
    <!--
      Pause-on-hover lives on the stack, not on each toast. Reaching for the
      dismiss button on the third toast means crossing the first two, and
      per-toast timers would keep expiring underneath the pointer while the
      operator is still moving toward a target. Pausing the whole stack is both
      the better behaviour and the one that does not need an invented role on
      each item.
    -->
    <div
        class="wg-toast-host"
        role="status"
        aria-live="polite"
        aria-label="Notifications"
        onmouseenter={holdAll}
        onmouseleave={resumeAll}
        onfocusin={holdAll}
        onfocusout={resumeAll}
    >
        {#each toasts.items as t (t.id)}
            <div
                class="wg-toast wg-toast-{t.tone}"
                role={t.tone === 'error' ? 'alert' : undefined}
            >
                <span
                    class="wg-toast-marker wg-marker-{TONE_SHAPE[t.tone]}"
                    style="--marker: var({TONE_TOKEN[t.tone]})"
                    aria-hidden="true"
                ></span>

                <div class="wg-toast-content">
                    <p class="wg-toast-title">
                        {t.title}
                        {#if t.count > 1}
                            <span class="wg-toast-count">×{t.count}</span>
                        {/if}
                    </p>
                    {#if t.detail}
                        <p class="wg-toast-detail">{t.detail}</p>
                    {/if}
                    {#if t.action}
                        <button
                            type="button"
                            class="wg-toast-action"
                            onclick={() => {
                                t.action?.run()
                                toasts.dismiss(t.id)
                            }}
                        >
                            {t.action.label}
                        </button>
                    {/if}
                </div>

                <button
                    type="button"
                    class="wg-toast-close"
                    aria-label="Dismiss: {t.title}"
                    onclick={() => toasts.dismiss(t.id)}
                >
                    <svg
                        viewBox="0 0 16 16"
                        width="12"
                        height="12"
                        aria-hidden="true"
                    >
                        <path
                            d="M4 4l8 8M12 4l-8 8"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.75"
                            stroke-linecap="round"
                        />
                    </svg>
                </button>
            </div>
        {/each}
    </div>
{/if}

<style>
    .wg-toast-host {
        position: fixed;
        right: var(--wg-space-lg);
        bottom: var(--wg-space-lg);
        z-index: 1100;
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-sm);
        width: min(100vw - 2 * var(--wg-space-lg), 24rem);
    }

    .wg-toast {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-sm);
        padding: var(--wg-space-md);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-left: 2px solid var(--tone, var(--wg-border-strong));
        border-radius: var(--wg-radius-panel);
        box-shadow: var(--wg-shadow-overlay);
        color: var(--wg-text);
        animation: wg-toast-in var(--wg-duration-normal) var(--wg-easing);
    }

    .wg-toast-info {
        --tone: var(--wg-primary);
    }
    .wg-toast-success {
        --tone: var(--wg-tertiary);
    }
    .wg-toast-warning {
        --tone: var(--wg-secondary);
    }
    .wg-toast-error {
        --tone: var(--wg-error);
    }

    @keyframes wg-toast-in {
        from {
            opacity: 0;
            transform: translateY(var(--wg-space-sm));
        }
    }

    @media (prefers-reduced-motion: reduce) {
        .wg-toast {
            animation: none;
        }
    }

    .wg-toast-marker {
        flex: none;
        width: var(--wg-marker-size);
        height: var(--wg-marker-size);
        /* optical centring against the first line of the title */
        margin-top: 0.4rem;
    }

    .wg-marker-dot {
        background: var(--marker);
        border-radius: var(--wg-radius-full);
    }

    .wg-marker-ring {
        width: 7px;
        height: 7px;
        border: 1.5px solid var(--marker);
        border-radius: var(--wg-radius-full);
    }

    .wg-marker-diamond {
        background: var(--marker);
        transform: rotate(45deg);
    }

    .wg-marker-triangle {
        width: 0;
        height: 0;
        border-left: 3.5px solid transparent;
        border-right: 3.5px solid transparent;
        border-bottom: 6px solid var(--marker);
    }

    .wg-toast-content {
        flex: 1 1 auto;
        min-width: 0;
    }

    .wg-toast-title {
        margin: 0;
        font: var(--wg-text-label-md);
    }

    .wg-toast-count {
        color: var(--wg-text-muted);
        font-variant-numeric: tabular-nums;
    }

    .wg-toast-detail {
        margin: var(--wg-space-xs) 0 0;
        font: var(--wg-text-label-sm);
        color: var(--wg-text-muted);
        overflow-wrap: anywhere;
    }

    .wg-toast-action {
        margin-top: var(--wg-space-sm);
        padding: 0;
        border: 0;
        background: none;
        color: var(--wg-primary);
        font: var(--wg-text-label-md);
        cursor: pointer;
        text-decoration: underline;
    }

    .wg-toast-close {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        flex: none;
        width: 1.25rem;
        height: 1.25rem;
        padding: 0;
        border: 0;
        border-radius: var(--wg-radius-sm);
        background: none;
        color: var(--wg-text-muted);
        cursor: pointer;
    }

    .wg-toast-close:hover {
        background: var(--wg-surface-container-high);
        color: var(--wg-text);
    }

    .wg-toast-action:focus-visible,
    .wg-toast-close:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }
</style>
