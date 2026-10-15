<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import { api, type Target } from 'admin/lib/api'
    import { TargetKind } from 'gateway/lib/api'

    interface Props {
        value: string | undefined
        /** Target that may not be its own jump host */
        excludeTargetId?: string
    }

    let { value = $bindable(), excludeTargetId }: Props = $props()

    let sshTargets = $state<Target[]>([])

    api.getTargets().then(targets => {
        sshTargets = targets.filter(
            t => t.options.kind === TargetKind.Ssh && t.id !== excludeTargetId,
        )
    })
</script>

{#if sshTargets.length}
    <div class="col">
        <FormGroup floating label="Jump host">
            <select
                class="form-control"
                bind:value={() => value ?? '', v => value = v || undefined}
            >
                <option value="">Direct connection</option>
                {#each sshTargets as target (target.id)}
                    <option value={target.id}>{target.name}</option>
                {/each}
            </select>
        </FormGroup>
    </div>
{/if}
