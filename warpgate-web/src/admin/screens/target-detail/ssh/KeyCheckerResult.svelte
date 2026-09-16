<script lang="ts" module>
    export class Key {
        constructor(
            public type: string,
            public publicKeyBase64: string,
        ) {}

        toString(): string {
            return `${this.type} ${this.publicKeyBase64}`
        }
    }

    export type CheckResult =
        | { state: 'key-valid' }
        | { state: 'key-invalid'; trustedKeys: Key[]; actualKey: Key }
        | { state: 'key-unknown'; actualKey: Key }
</script>

<script lang="ts">
    /**
     * The three outcomes of an SSH host-key check, on Callout.
     *
     * `key-invalid` is forced assertive. Callout's default is polite for
     * everything but danger, and this *is* danger — but it also appears on
     * navigation rather than after an action, which is normally the case for
     * staying polite. It is the host-key-changed warning: the one message in
     * the product where interrupting a screen reader mid-sentence is the
     * entire point.
     */
    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import Callout from 'ui/Callout.svelte'

    interface Props {
        result: CheckResult
    }

    let { result }: Props = $props()
</script>

{#if result.state === 'key-valid'}
    <Callout tone="success" title="Remote host key is trusted" />
{/if}

{#if result.state === 'key-unknown'}
    <Callout tone="warning" title="Remote host key is not trusted yet">
        <CopyableTextArea
            label="Remote key"
            value={`${result.actualKey.type} ${result.actualKey.publicKeyBase64}`}
        />
    </Callout>
{/if}

{#if result.state === 'key-invalid'}
    <Callout tone="danger" assertive title="Remote host key has changed">
        <p class="warn">
            The key this host is presenting does not match the one Warpgate
            trusts. Either the host was rebuilt or rekeyed, or the connection is
            being intercepted. Confirm the new key out of band before trusting
            it.
        </p>
        {#if result.trustedKeys.length}
            {#each result.trustedKeys as key (key)}
                <CopyableTextArea
                    label="Known trusted key"
                    value={`${key.type} ${key.publicKeyBase64}`}
                />
            {/each}
        {/if}
        <CopyableTextArea
            label="Current remote key"
            value={`${result.actualKey.type} ${result.actualKey.publicKeyBase64}`}
        />
    </Callout>
{/if}

<style>
    .warn {
        margin: 0 0 var(--wg-space-sm);
        color: var(--wg-text);
    }
</style>
