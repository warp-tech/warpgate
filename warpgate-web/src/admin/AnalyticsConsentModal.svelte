<script lang="ts">
    import { AnalyticsConsent, api } from 'admin/lib/api'
    import { reloadServerInfo } from 'gateway/lib/store'
    import Button from 'ui/Button.svelte'
    import Modal from 'ui/Modal.svelte'
    import AnalyticsPreview from './AnalyticsPreview.svelte'
    import HelpText from './lib/HelpText.svelte'

    interface Props {
        isOpen?: boolean
        initialConsent?: AnalyticsConsent
        initialNormal?: boolean
        onsaved?: () => void
    }

    let {
        isOpen = $bindable(false),
        initialConsent,
        initialNormal = false,
        onsaved,
    }: Props = $props()

    type Choice = 'normal' | 'reduced' | 'off'

    function initialChoice(): Choice {
        if (initialConsent === AnalyticsConsent.Off) {
            return 'off'
        }
        if (initialConsent === AnalyticsConsent.On) {
            return initialNormal ? 'normal' : 'reduced'
        }
        return 'normal'
    }

    let choice = $state<Choice>(initialChoice())

    // Reset the selection each time the modal is (re)opened.
    let wasOpen = false
    $effect(() => {
        if (isOpen && !wasOpen) {
            choice = initialChoice()
        }
        wasOpen = isOpen
    })

    async function save() {
        const consent =
            choice === 'off' ? AnalyticsConsent.Off : AnalyticsConsent.On
        await api.updateParameters({
            parameterUpdate: {
                analyticsConsent: consent,
                analyticsNormal: choice === 'normal',
            },
        })
        await reloadServerInfo()
        isOpen = false
        onsaved?.()
    }
</script>

<Modal open={isOpen} title="Installation counter" size="lg">
    <p>
        Warpgate can send a heartbeat request so that the project can count
        active installations and their sizes. It's off unless you enable it.
    </p>

    <p>
        Below, you can see the exact payload that would get sent - nothing more.
    </p>

    <div class="consent-grid">
        {#if choice !== 'off'}
            <div class="consent-preview">
                <AnalyticsPreview normal={choice === 'normal'} />
            </div>
        {/if}

        <div class="consent-choices">
            <label class="choice">
                <input type="radio" bind:group={choice} value="normal">
                <div>Version + approximate stats</div>
            </label>
            <label class="choice">
                <input type="radio" bind:group={choice} value="reduced">
                <div>Version only</div>
            </label>
            <label class="choice">
                <input type="radio" bind:group={choice} value="off">
                <div>Nothing at all</div>
            </label>
            <HelpText class="mt-3">
                You can change this later under <em>Global Parameters</em>.
            </HelpText>
            {#if choice !== 'off'}
                <HelpText>
                    Warpgate uses OpenPanel, which is an open-source statistics
                    platform. It is hosted in the EU, does not store IP
                    addresses and is GDPR compliant.
                </HelpText>
                <HelpText>
                    The instance ID is random and is not derived from the
                    environment.
                </HelpText>
                <HelpText> Only a single heartbeat is sent per day. </HelpText>
            {/if}
        </div>
    </div>

    {#snippet footer()}
        <Button variant="primary" click={save}>Save selection</Button>
    {/snippet}
</Modal>

<style>
    .consent-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
        gap: var(--wg-space-xl);
        margin-top: var(--wg-space-xl);
    }

    .consent-preview,
    .consent-choices {
        min-width: 0;
    }

    .choice {
        display: flex;
        align-items: center;
        gap: var(--wg-space-sm);
        margin-bottom: var(--wg-space-sm);
        font: var(--wg-text-body-md);
        cursor: pointer;
    }

    .choice input {
        accent-color: var(--wg-primary);
    }

    .choice input:focus-visible {
        outline: var(--wg-focus-ring);
        outline-offset: var(--wg-focus-ring-offset);
    }
</style>
