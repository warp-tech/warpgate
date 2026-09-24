<script lang="ts">
    /**
     * First-run checklist, shown on the admin session list and the portal
     * target list until dismissed.
     *
     * Behaviour preserved: the three entries, the tick that reflects
     * setupState.hasTargets / hasUsers, the external docs link, and Dismiss
     * calling dismissTutorial then reloading server info.
     *
     * Changed: the completion state was a FontAwesome circle vs circle-check
     * with no text alternative, so a screen reader user could not tell a done
     * step from a pending one. Each row now says "Done" or "To do" in a
     * visually hidden span, and the tick is decorative.
     */
    import { api, type SetupState } from 'gateway/lib/api'
    import { reloadServerInfo } from 'gateway/lib/store'
    import Button from 'ui/Button.svelte'

    interface Props {
        setupState: SetupState
    }

    let { setupState }: Props = $props()

    async function dismiss() {
        await api.dismissTutorial()
        await reloadServerInfo()
    }

    const steps = $derived([
        {
            href: 'https://warpgate.null.page/docs/?utm_source=app&utm_content=getting-started',
            external: true,
            done: false,
            title: 'Check out the documentation',
            hint: undefined as string | undefined,
        },
        {
            href: '/@warpgate/admin#/config/targets/create',
            external: false,
            done: setupState.hasTargets,
            title: 'Add a target',
            hint: 'Targets are the servers and services your users connect to through Warpgate',
        },
        {
            href: '/@warpgate/admin#/config/users/create',
            external: false,
            done: setupState.hasUsers,
            title: 'Add a non-admin user',
            hint: 'Create separate non-admin accounts for your users',
        },
    ])
</script>

<section class="getting-started">
    <header>
        <h2>Getting started</h2>
        <Button variant="ghost" size="compact" click={dismiss}>Dismiss</Button>
    </header>

    <ul>
        {#each steps as step (step.href)}
            <li>
                <a
                    href={step.href}
                    target={step.external ? '_blank' : undefined}
                    rel={step.external ? 'noreferrer' : undefined}
                >
                    <span
                        class="tick"
                        class:tick-done={step.done}
                        aria-hidden="true"
                    >
                        {#if step.done}
                            <svg
                                viewBox="0 0 16 16"
                                width="14"
                                height="14"
                                aria-hidden="true"
                            >
                                <circle
                                    cx="8"
                                    cy="8"
                                    r="6.25"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="1.4"
                                />
                                <path
                                    d="M5 8.2l2.1 2.1L11 6.4"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="1.6"
                                    stroke-linecap="round"
                                    stroke-linejoin="round"
                                />
                            </svg>
                        {:else}
                            <svg
                                viewBox="0 0 16 16"
                                width="14"
                                height="14"
                                aria-hidden="true"
                            >
                                <circle
                                    cx="8"
                                    cy="8"
                                    r="6.25"
                                    fill="none"
                                    stroke="currentColor"
                                    stroke-width="1.4"
                                />
                            </svg>
                        {/if}
                    </span>

                    <span class="step-text">
                        <span class="step-title">
                            {step.title}
                            {#if !step.external}
                                <span class="sr-only">
                                    — {step.done ? 'Done' : 'To do'}
                                </span>
                            {/if}
                        </span>
                        {#if step.hint}
                            <span class="step-hint">{step.hint}</span>
                        {/if}
                    </span>

                    {#if step.external}
                        <span class="go" aria-hidden="true">↗</span>
                    {/if}
                </a>
            </li>
        {/each}
    </ul>
</section>

<style>
    .getting-started {
        margin-bottom: var(--wg-space-3xl);
        padding: var(--wg-space-xl);
        background: var(--wg-surface-container);
        border: var(--wg-border-width) solid var(--wg-border);
        border-radius: var(--wg-radius-panel);
    }

    header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: var(--wg-space-md);
        margin-bottom: var(--wg-space-md);
    }

    h2 {
        margin: 0;
        font: var(--wg-text-headline-md);
    }

    ul {
        list-style: none;
        margin: 0;
        padding: 0;
    }

    li + li {
        border-top: var(--wg-border-width) solid var(--wg-border);
    }

    a {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-md);
        padding: var(--wg-space-md) 0;
        color: var(--wg-text);
        text-decoration: none;
    }

    .step-title {
        font: var(--wg-text-body-md);
    }

    a:hover .step-title {
        text-decoration: underline;
    }

    a:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }

    .tick {
        flex: none;
        margin-top: 2px;
        color: var(--wg-text-subtle);
    }

    .tick-done {
        color: var(--wg-tertiary);
    }

    .step-text {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
        margin-right: auto;
    }

    .step-hint {
        color: var(--wg-text-muted);
        font: var(--wg-text-label-sm);
    }

    .go {
        flex: none;
        color: var(--wg-text-muted);
    }

    .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip-path: inset(50%);
        white-space: nowrap;
        border: 0;
    }
</style>
