<script lang="ts">
    import { faPlus, faTimes } from '@fortawesome/free-solid-svg-icons'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import { type PortKnocking, PortKnockProtocol } from 'admin/lib/api'
    import Fa from 'svelte-fa'

    interface Props {
        value: PortKnocking | undefined
        disabled?: boolean
    }

    // Keep in sync with warpgate-common/src/helpers/port_knock.rs
    const MAX_SEQUENCE_LENGTH = 32
    const MAX_DELAY_MS = 10000
    const MAX_WAIT_AFTER_MS = 30000

    let { value = $bindable(), disabled = false }: Props = $props()

    function toggle(enabled: boolean) {
        value = enabled
            ? {
                  sequence: [{ port: 7000, protocol: PortKnockProtocol.Tcp }],
                  delayMs: 100,
                  waitAfterMs: 500,
              }
            : undefined
    }

    function addKnock() {
        value?.sequence.push({ port: 7000, protocol: PortKnockProtocol.Tcp })
    }

    function removeKnock(index: number) {
        value?.sequence.splice(index, 1)
    }
</script>

<label for="portKnockingEnabled" class="d-flex align-items-center mb-2">
    <Input
        id="portKnockingEnabled"
        class="mb-0 me-2"
        type="switch"
        {disabled}
        checked={!!value}
        on:change={e => toggle((e.target as HTMLInputElement).checked)}
    />
    <div>Knock on ports before connecting</div>
</label>

<small class="form-text text-muted d-block mb-3">
    Warpgate sends these packets to the target host, in order, before every
    connection. Only the target itself is knocked, not the hosts behind an SSH
    jump host.
</small>

{#if value}
    <FormGroup>
        {#each value.sequence as knock, index (index)}
            <div class="d-flex gap-3 mb-2">
                <input
                    class="form-control flex-grow-1"
                    type="number"
                    placeholder="Port"
                    min="1"
                    max="65535"
                    step="1"
                    {disabled}
                    bind:value={knock.port}
                >
                <Input type="select" {disabled} bind:value={knock.protocol}>
                    <option value={PortKnockProtocol.Tcp}>TCP</option>
                    <option value={PortKnockProtocol.Udp}>UDP</option>
                </Input>
                <button
                    type="button"
                    class="btn btn-link px-0"
                    disabled={disabled || value.sequence.length <= 1}
                    onclick={() => removeKnock(index)}
                    title="Remove"
                >
                    <Fa icon={faTimes} />
                </button>
            </div>
        {/each}

        {#if value.sequence.length < MAX_SEQUENCE_LENGTH}
            <button
                type="button"
                class="btn btn-secondary btn-sm d-flex align-items-center gap-2"
                {disabled}
                onclick={addKnock}
            >
                <Fa icon={faPlus} />
                Add knock
            </button>
        {/if}
    </FormGroup>

    <div class="row">
        <div class="col">
            <FormGroup floating label="Delay between knocks (ms)">
                <input
                    class="form-control"
                    type="number"
                    min="0"
                    max={MAX_DELAY_MS}
                    step="1"
                    {disabled}
                    bind:value={value.delayMs}
                >
            </FormGroup>
        </div>
        <div class="col">
            <FormGroup floating label="Wait before connecting (ms)">
                <input
                    class="form-control"
                    type="number"
                    min="0"
                    max={MAX_WAIT_AFTER_MS}
                    step="1"
                    {disabled}
                    bind:value={value.waitAfterMs}
                >
            </FormGroup>
        </div>
    </div>
{/if}
