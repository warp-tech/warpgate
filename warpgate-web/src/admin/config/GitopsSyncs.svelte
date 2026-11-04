<script lang="ts">
    import { Alert, Input } from '@sveltestrap/sveltestrap'
    import {
        api,
        type ProviderSync,
        SyncStatus,
        SyncTrigger,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import ItemList, { type LoadOptions } from 'common/ItemList.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { from } from 'rxjs'
    import { link } from 'svelte-spa-router'

    const TRIGGERS: Record<SyncTrigger, string> = {
        [SyncTrigger.Startup]: 'startup',
        [SyncTrigger.Interval]: 'interval',
        [SyncTrigger.Api]: 'manual',
        [SyncTrigger.Webhook]: 'webhook',
    }

    let forcePrune = $state(false)
    let error: string | undefined = $state()
    let gen = $state(0)

    function load(opt: LoadOptions) {
        return from(
            api.getGitopsSyncs({ offset: opt.offset, limit: opt.limit }),
        )
    }

    async function sync(): Promise<void> {
        error = undefined
        try {
            await api.syncGitops({
                syncGitopsRequest: { forcePrune },
            })
        } catch (err) {
            error = await stringifyError(err)
        }
        gen++
    }

    // "2 create, 1 delete": the plan is a list of changes tagged by action
    function summarize(row: ProviderSync): string {
        const counts = new Map<string, number>()
        for (const { action } of (row.plan ?? []) as { action: string }[]) {
            if (action !== 'unchanged') {
                counts.set(action, (counts.get(action) ?? 0) + 1)
            }
        }
        return [...counts]
            .map(([action, n]) => `${n} ${action.replace('_', ' ')}`)
            .join(', ')
    }
</script>

<div class="page-summary-bar">
    <h1>gitops syncs</h1>
    {#if $adminPermissions.configEdit}
        <div class="ms-auto d-flex align-items-center gap-3">
            <a href="/config/gitops/settings" use:link>Settings</a>
            <Input
                type="switch"
                label="Force prune"
                bind:checked={forcePrune}
            />
            <AsyncButton color="primary" click={sync}>Sync now</AsyncButton>
        </div>
    {/if}
</div>

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#key gen}
    <ItemList {load} pageSize={100}>
        {#snippet item(row)}
            <div class="list-group-item px-0">
                <div class="d-flex align-items-center gap-2">
                    <strong
                        class:text-danger={row.status === SyncStatus.Failed}
                    >
                        {row.status}
                    </strong>
                    <span class="text-muted">{TRIGGERS[row.triggeredBy]}</span>
                    {#if row.revision}
                        <code>{row.revision.slice(0, 12)}</code>
                    {/if}
                    <span class="text-muted">{summarize(row)}</span>
                    <span class="ms-auto text-muted">
                        <RelativeDate date={row.startedAt} />
                    </span>
                </div>
                <div class="text-muted small">
                    {row.source}
                    · last checked
                    <RelativeDate date={row.checkedAt} />
                </div>
                {#if row.error}
                    <pre class="small text-danger mt-1 mb-0">{row.error}</pre>
                {/if}
            </div>
        {/snippet}
        {#snippet empty()}
            <EmptyState
                title="No syncs yet"
                hint="Set a source in GitOps settings"
            />
        {/snippet}
    </ItemList>
{/key}

<style>
    pre {
        white-space: pre-wrap;
    }
</style>
