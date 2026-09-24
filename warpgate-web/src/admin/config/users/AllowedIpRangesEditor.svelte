<script lang="ts">
    /**
     * Allowed IP ranges (CIDR) for a user.
     *
     * Behaviour preserved: the same CIDR regex for v4 and v6, an empty value
     * treated as valid (the field is optional per row), add/remove, and the
     * explanatory note that an empty list allows all addresses.
     *
     * Changed: the per-row error was a `<small>` nudged up with a negative
     * margin and tied to its field by proximity alone. ui/Input takes `error`
     * and wires it to the input with aria-describedby, so a screen reader
     * hears which row is wrong.
     */
    import Button from 'ui/Button.svelte'
    import Input from 'ui/Input.svelte'

    interface Props {
        ranges: string[] | null | undefined
    }

    let { ranges = $bindable() }: Props = $props()

    const cidrRegex =
        /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$|^[0-9a-fA-F:]+\/\d{1,3}$/

    function isValidCidr(value: string | undefined | null): boolean {
        if (!value?.trim()) {
            return true
        }
        return cidrRegex.test(value.trim())
    }

    function errorFor(range: string | undefined): string | undefined {
        return range?.trim() && !isValidCidr(range)
            ? 'Not CIDR notation. Use 192.168.1.0/24, or 1.2.3.4/32 for one address.'
            : undefined
    }

    function addIpRange() {
        ranges = [...(ranges ?? []), '']
    }

    function removeIpRange(index: number) {
        if (!ranges) {
            return
        }
        ranges = ranges.filter((_, i) => i !== index)
    }
</script>

<div class="ranges">
    <span class="group-label">Allowed IP ranges (CIDR)</span>

    {#if ranges?.length}
        {#each ranges as range, index (index)}
            <div class="row">
                <div class="row-field">
                    <Input
                        label="IP range {index + 1}"
                        labelHidden
                        mono
                        placeholder="e.g. 192.168.1.0/24"
                        value={range}
                        error={errorFor(range)}
                        oninput={e => {
                            if (ranges) {
                                ranges[index] = (
                                    e.target as HTMLInputElement
                                ).value
                                ranges = [...ranges]
                            }
                        }}
                    />
                </div>
                <Button
                    variant="ghost"
                    size="compact"
                    label="Remove IP range {index + 1}"
                    onclick={() => removeIpRange(index)}
                >
                    <svg
                        viewBox="0 0 16 16"
                        width="14"
                        height="14"
                        aria-hidden="true"
                    >
                        <path
                            d="M3 4.5h10M6.5 4.5V3h3v1.5M4.5 4.5l.6 8.2a1 1 0 0 0 1 .8h3.8a1 1 0 0 0 1-.8l.6-8.2"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.4"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        />
                    </svg>
                </Button>
            </div>
        {/each}
    {/if}

    <div class="add">
        <Button size="compact" onclick={addIpRange}>Add IP range</Button>
    </div>

    <p class="note">
        If set, only connections from these ranges are allowed. Leave the list
        empty to allow every address.
    </p>
</div>

<style>
    .ranges {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-xs);
    }

    .group-label {
        font: var(--wg-text-body-md);
        color: var(--wg-text-muted);
    }

    .row {
        display: flex;
        align-items: flex-start;
        gap: var(--wg-space-sm);
    }

    .row-field {
        flex: 1 1 auto;
        min-width: 0;
    }

    .add {
        display: flex;
        margin-top: var(--wg-space-xs);
    }

    .note {
        margin: var(--wg-space-xs) 0 0;
        color: var(--wg-text-subtle);
        font: var(--wg-text-label-sm);
        max-width: 70ch;
    }
</style>
