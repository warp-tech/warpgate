<script lang="ts">
    import { Input, Button } from '@sveltestrap/sveltestrap'
    import Fa from 'svelte-fa'
    import { faPlus, faTrash } from '@fortawesome/free-solid-svg-icons'

    interface Props {
        ranges: string[] | null | undefined;
    }

    let { ranges = $bindable() }: Props = $props()

    const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/
    function isValidCidr (value: string | undefined | null): boolean {
        if (!value?.trim()) {return true}
        return cidrRegex.test(value.trim())
    }

    function addIpRange () {
        if (!ranges) {ranges = []}
        ranges = [...ranges, '']
    }

    function removeIpRange (index: number) {
        if (!ranges) {return}
        ranges = ranges.filter((_, i) => i !== index)
    }
</script>

<div>
    <!-- svelte-ignore a11y_label_has_associated_control -->
    <label class="form-label">Allowed IP ranges (CIDR)</label>
    {#if ranges?.length}
        {#each ranges as range, index (index)}
            <div class="d-flex align-items-center mb-2 gap-2">
                <Input
                    placeholder="e.g. 192.168.1.0/24"
                    value={range}
                    on:input={(e) => {
                        if (ranges) {
                            ranges[index] = e.target.value
                            ranges = [...ranges]
                        }
                    }}
                    invalid={!!range?.trim() && !isValidCidr(range)}
                />
                <Button
                    color="link"
                    size="sm"
                    on:click={() => removeIpRange(index)}
                >
                    <Fa icon={faTrash} />
                </Button>
            </div>
            {#if range?.trim() && !isValidCidr(range)}
                <small class="form-text text-danger d-block mb-2" style="margin-top: -0.5rem">
                    Invalid CIDR notation. Use a format like 192.168.1.0/24 or 10.0.0.1/32.
                </small>
            {/if}
        {/each}
    {/if}
    <Button
        class="d-flex align-items-center gap-2"
        color="secondary"
        size="sm"
        on:click={addIpRange}
    >
        <Fa icon={faPlus} class="me-1" />
        <div>Add IP range</div>
    </Button>
    <small class="form-text text-muted d-block mt-2">
        If set, only connections from these IP ranges will be allowed. Use CIDR notation (e.g. 10.0.0.0/8, 192.168.1.0/24, or a single IP like 1.2.3.4/32). Leave empty to allow all IPs.
    </small>
</div>
