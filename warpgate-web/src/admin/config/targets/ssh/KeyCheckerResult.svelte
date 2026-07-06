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
        | {
              state: 'key-valid'
          }
        | {
              state: 'key-invalid'
              trustedKeys: Key[]
              actualKey: Key
          }
        | {
              state: 'key-unknown'
              actualKey: Key
          }
</script>
<script lang="ts">
    import { faCheck, faWarning } from '@fortawesome/free-solid-svg-icons'

    import { Alert } from '@sveltestrap/sveltestrap'
    import CopyableTextArea from 'common/CopyableTextArea.svelte'
    import Fa from 'svelte-fa'

    interface Props {
        result: CheckResult
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
        <CopyableTextArea
            label="Remote key"
            value={`${result.actualKey.type} ${result.actualKey.publicKeyBase64}`}
        />
    </Alert>
{/if}

{#if result.state === 'key-invalid'}
    <Alert color="danger" class="d-flex align-items-center">
        <Fa icon={faWarning} class="me-3" />
        <div style="min-width: 0">
            <h5>Remote host key has changed!</h5>
            {#if result.trustedKeys.length}
                <div class="mb-2">
                    {#each result.trustedKeys as key (key)}
                        <CopyableTextArea
                            label="Known trusted key"
                            value={`${key.type} ${key.publicKeyBase64}`}
                        />
                    {/each}
                </div>
            {/if}
            <CopyableTextArea
                label="Current remote key"
                value={`${result.actualKey.type} ${result.actualKey.publicKeyBase64}`}
            />
        </div>
    </Alert>
{/if}
