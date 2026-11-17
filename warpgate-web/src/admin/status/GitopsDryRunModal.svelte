<script lang="ts">
    import {
        Alert,
        Badge,
        Button,
        type Color,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import { type DryRun, PlanAction } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'

    interface Props {
        /** The modal is open while this is set */
        dryRun: DryRun | undefined
        sync: () => Promise<void>
    }

    let { dryRun = $bindable(), sync }: Props = $props()

    const ACTIONS: Record<PlanAction, { label: string; color: Color }> = {
        [PlanAction.Create]: { label: 'Create', color: 'success' },
        [PlanAction.Update]: { label: 'Update', color: 'warning' },
        [PlanAction.Adopt]: { label: 'Adopt', color: 'warning' },
        [PlanAction.Delete]: { label: 'Delete', color: 'danger' },
        [PlanAction.Blocked]: { label: 'Blocked', color: 'danger' },
        [PlanAction.Collision]: { label: 'Collision', color: 'danger' },
        [PlanAction.WouldPrune]: {
            label: 'Keep (pruning is off)',
            color: 'secondary',
        },
        [PlanAction.Unchanged]: { label: 'Unchanged', color: 'secondary' },
    }
    const PENDING: PlanAction[] = [
        PlanAction.Create,
        PlanAction.Update,
        PlanAction.Adopt,
        PlanAction.Delete,
    ]

    const plan = $derived(dryRun?.plan ?? [])
    const changes = $derived(
        plan.filter(c => c.action !== PlanAction.Unchanged),
    )
    const pending = $derived(changes.some(c => PENDING.includes(c.action)))

    function close() {
        dryRun = undefined
    }
</script>

<Modal isOpen={!!dryRun} toggle={close} size="lg">
    <ModalBody>
        {#if dryRun}
            <div class="text-muted small mb-3">
                From {dryRun.source}
                {#if dryRun.revision}
                    at <code>{dryRun.revision.slice(0, 12)}</code>
                {/if}
            </div>
            {#if dryRun.error}
                <Alert color="danger"
                    ><pre class="mb-0">{dryRun.error}</pre></Alert
                >
            {/if}
            {#each changes as change, i (i)}
                {@const action = ACTIONS[change.action]}
                <div class="mb-2">
                    <div class="mb-2">
                        <Badge color={action.color}> {action.label} </Badge>
                        <Badge color="secondary"> {change.kind} </Badge>
                        <strong>{change.name}</strong>
                        {#if change.reason}
                            <div class="text-muted small">{change.reason}</div>
                        {/if}
                    </div>
                    {#each change.fields as field (field.path)}
                        <div class="small font-monospace ms-4">
                            {field.path}:
                            {#if field.credential}
                                <Badge color="warning" class="font-monospace">
                                    Changed
                                </Badge>
                            {:else}
                                <Badge color="success" class="font-monospace">
                                    + {JSON.stringify(field.to ?? null)}
                                </Badge>
                                <Badge color="danger" class="font-monospace">
                                    - {JSON.stringify(field.from ?? null)}
                                </Badge>
                            {/if}
                        </div>
                    {/each}
                </div>
            {/each}
            {#if plan.length > changes.length}
                <div class="text-muted">
                    {plan.length - changes.length}
                    unchanged
                </div>
            {/if}
            {#if !pending && !dryRun.error}
                <div>Nothing to apply.</div>
            {/if}
        {/if}
    </ModalBody>
    <ModalFooter>
        {#if pending && !dryRun?.error}
            <AsyncButton
                color="primary"
                class="modal-button"
                click={async () => {
                    await sync()
                    close()
                }}
            >
                Sync now
            </AsyncButton>
        {/if}
        <Button class="modal-button" color="secondary" onclick={close}>
            Close
        </Button>
    </ModalFooter>
</Modal>

<style>
    pre {
        white-space: pre-wrap;
    }
</style>
