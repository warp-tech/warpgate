<script lang="ts">
    import { api, type UserRoleHistoryEntry, type PaginatedResponseUserRoleHistoryEntry } from 'admin/lib/api'
    import { Modal, ModalBody, ModalFooter, Button } from '@sveltestrap/sveltestrap'
    import ModalHeader from 'common/sveltestrap-s5-ports/ModalHeader.svelte'
    import Loadable from 'common/Loadable.svelte'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import RelativeDate from '../../RelativeDate.svelte'

    interface Props {
        open: boolean
        userId: string
        roleId: string
    }

    let { open = $bindable(false), userId, roleId }: Props = $props()

    let history: UserRoleHistoryEntry[] = $state([])

    async function loadHistory() {
        const response: PaginatedResponseUserRoleHistoryEntry = await api.getUserRoleHistory({ id: userId, roleId })
        history = response.items
        return history
    }

    function getActionLabel(action: string): string {
        switch (action) {
            case 'granted':
                return 'Role granted'
            case 'revoked':
                return 'Role revoked'
            case 'expiry_changed':
                return 'Expiry updated'
            case 'expiry_removed':
                return 'Expiry removed'
            default:
                return action
        }
    }

    function getActionColor(action: string): string {
        switch (action) {
            case 'granted':
                return 'success'
            case 'revoked':
                return 'danger'
            case 'expiry_changed':
                return 'warning'
            case 'expiry_removed':
                return 'info'
            default:
                return 'secondary'
        }
    }

    function formatDate(dateStr: string | Date | null | undefined): string {
        if (!dateStr) {
            return 'Never'
        }
        if (dateStr instanceof Date) {
            return dateStr.toLocaleString()
        }
        return new Date(dateStr).toLocaleString()
    }
</script>

<Modal isOpen={open} toggle={() => open = false} size="lg">
    <ModalHeader toggle={() => open = false}>
        Role Assignment History
    </ModalHeader>
    <ModalBody>
        {#if open}
            <Loadable promise={loadHistory()}>
                {#if history.length === 0}
                    <Alert color="info">No history entries found for this role assignment.</Alert>
                {:else}
                    <div class="timeline">
                        {#each history as entry (entry.id)}
                            <div class="timeline-item mb-3 pb-3 border-bottom">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <span class="badge bg-{getActionColor(entry.action)} me-2">
                                            {getActionLabel(entry.action)}
                                        </span>
                                        <span class="text-muted small">
                                            <RelativeDate date={new Date(entry.occurredAt)} />
                                        </span>
                                    </div>
                                    {#if entry.actorUsername}
                                        <small class="text-muted">by {entry.actorUsername}</small>
                                    {/if}
                                </div>

                                {#if entry.details}
                                    <div class="mt-2 ms-2 small text-muted">
                                        {#if entry.action === 'expiry_changed'}
                                            {#if entry.details.oldExpiresAt}
                                                <div>Previous expiry: {formatDate(entry.details.oldExpiresAt)}</div>
                                            {/if}
                                            {#if entry.details.newExpiresAt}
                                                <div>New expiry: {formatDate(entry.details.newExpiresAt)}</div>
                                            {:else}
                                                <div>New expiry: Never (permanent)</div>
                                            {/if}
                                        {:else if entry.action === 'granted'}
                                            {#if entry.details.expiresAt}
                                                <div>Expires: {formatDate(entry.details.expiresAt)}</div>
                                            {:else}
                                                <div>No expiry (permanent)</div>
                                            {/if}
                                        {/if}
                                    </div>
                                {/if}
                            </div>
                        {/each}
                    </div>
                {/if}
            </Loadable>
        {/if}
    </ModalBody>

    <ModalFooter>
        <Button color="secondary" on:click={() => open = false}>
            Close
        </Button>
    </ModalFooter>
</Modal>

<style>
    .timeline-item:last-child {
        border-bottom: none !important;
    }
</style>
