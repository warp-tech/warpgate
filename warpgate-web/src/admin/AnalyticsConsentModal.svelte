<script lang="ts">
    import { api, AnalyticsConsent } from 'admin/lib/api'
    import { reloadServerInfo } from 'gateway/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import AnalyticsPreview from './AnalyticsPreview.svelte'
    import { Modal, ModalBody, ModalFooter, ModalHeader } from '@sveltestrap/sveltestrap'
    import HelpText from './lib/HelpText.svelte'

    interface Props {
        isOpen?: boolean
        initialConsent?: AnalyticsConsent
        initialNormal?: boolean
        onsaved?: () => void
    }

    let { isOpen = $bindable(false), initialConsent, initialNormal = false, onsaved }: Props = $props()

    type Choice = 'normal' | 'reduced' | 'off'

    function initialChoice (): Choice {
        if (initialConsent === AnalyticsConsent.Off) { return 'off' }
        if (initialConsent === AnalyticsConsent.On) { return initialNormal ? 'normal' : 'reduced' }
        return 'normal'
    }

    let choice = $state<Choice>(initialChoice())

    // Reset the selection each time the modal is (re)opened.
    let wasOpen = false
    $effect(() => {
        if (isOpen && !wasOpen) { choice = initialChoice() }
        wasOpen = isOpen
    })

    async function save () {
        const consent = choice === 'off' ? AnalyticsConsent.Off : AnalyticsConsent.On
        await api.updateParameters({ parameterUpdate: {
            analyticsConsent: consent,
            analyticsNormal: choice === 'normal',
        } })
        await reloadServerInfo()
        isOpen = false
        onsaved?.()
    }
</script>

<Modal isOpen={isOpen} size="lg">
    <ModalHeader>Installation counter</ModalHeader>
    <ModalBody>
        <p>
            Warpgate can send a heartbeat request so that the project can count active installations and their sizes. It's off unless you enable it.
        </p>

        <p>
            Below, you can see the exact payload that would get sent - nothing more.
        </p>

        <div class="row mt-4">
            {#if choice !== 'off'}
                <div class="col mb-3">
                    <AnalyticsPreview normal={choice === 'normal'} />
                </div>
            {/if}

            <div class="col">
                <label class="choice">
                    <input type="radio" bind:group={choice} value="normal" />
                    <div>Version + approximate stats</div>
                </label>
                <label class="choice">
                    <input type="radio" bind:group={choice} value="reduced" />
                    <div>Version only</div>
                </label>
                <label class="choice">
                    <input type="radio" bind:group={choice} value="off" />
                    <div>Nothing at all</div>
                </label>
                <HelpText class="mt-3">
                    You can change this later under <em>Global Parameters</em>.
                </HelpText>
                {#if choice !== 'off'}
                <HelpText>
                    Warpgate uses OpenPanel, which is an open-source statistics platform. It is hosted in the EU, does not store IP addresses and is GDPR compliant.
                </HelpText>
                <HelpText>
                    The instance ID is random and is not derived from the environment.
                </HelpText>
                <HelpText>
                    Only a single heartbeat is sent per day.
                </HelpText>
                {/if}
            </div>
        </div>
    </ModalBody>
    <ModalFooter>
        <AsyncButton
            type="button"
            class="modal-button btn btn-success"
            click={save}
        >Save selection</AsyncButton>
    </ModalFooter>
</Modal>

<style lang="scss">
    .choice {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-bottom: 0.5rem;
    }
</style>
