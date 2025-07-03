<script lang="ts" module>
    export class Key {
        constructor (public type: string, public publicKeyBase64: string) { }

        toString (): string {
            return this.type + ' ' + this.publicKeyBase64
        }
    }

    export type CheckResult = {
        state: 'key-valid',
    } | {
        state: 'key-invalid',
        trustedKeys: Key[],
        actualKey: Key
    } | {
        state: 'key-unknown',
        actualKey: Key,
    }

</script>
<script lang="ts">
    import { faCheck, faWarning } from '@fortawesome/free-solid-svg-icons'
    import CopyButton from 'common/CopyButton.svelte'

    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Fa from 'svelte-fa'

    interface Props {
        result: CheckResult,
    }

    let { result }: Props = $props()
</script>


{#if result.state === 'key-valid'}
<Alert color="success" class="d-flex align-items-center">
    <Fa icon={faCheck} class="me-3" />
    Remote host key is trusted
</Alert>
{/if}
{#if result.state === 'key-unknown'}
<Alert color="warning">
    <div>Remote host key is not trusted yet</div>
    <pre class="key-value">{result.actualKey} <CopyButton link text={result.actualKey.toString()} class="copy-button" /></pre>
</Alert>
{/if}

{#if result.state === 'key-invalid'}
<Alert color="danger" class="d-flex align-items-center">
    <Fa icon={faWarning} class="me-3" />
    <div style="min-width: 0">
        <h5>Remote host key has changed!</h5>
        {#if result.trustedKeys.length}
            <strong>Known trusted keys:</strong>
            <div class="mb-2">
                {#each result.trustedKeys as key (key)}
                    <pre class="key-value">{key} <CopyButton link text={key.toString()} class="copy-button" /></pre>
                {/each}
            </div>
        {/if}
        <strong>Current remote key:</strong>
        <pre class="key-value">{result.actualKey} <CopyButton link text={result.actualKey.toString()} class="copy-button" /></pre>
    </div>
</Alert>
{/if}

<style lang="scss">
    .key-value {
        word-wrap: break-word;
        margin-bottom: 0;
        white-space: break-spaces;

        background: rgba(0, 0, 0, .5);
        border-radius: 3px;
        padding: 5px 10px;

        :global(.copy-button) {
            float: right;
            margin-left: 0.5rem;
        }
    }
</style>
