<script lang="ts">
    import { Alert, Badge } from '@sveltestrap/sveltestrap'
    import {
        api,
        type DryRun,
        type GitopsHistoryLatest,
        PlanAction,
        type ProviderSync,
        SyncStatus,
        SyncTrigger,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import EmptyState from 'common/EmptyState.svelte'
    import { stringifyError } from 'common/errors'
    import ItemList, { type LoadOptions } from 'common/ItemList.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RelativeDate from 'common/RelativeDate.svelte'
    import { from } from 'rxjs'
    import { link } from 'svelte-spa-router'
    import GitopsDryRunModal from './GitopsDryRunModal.svelte'

    const TRIGGERS: Record<SyncTrigger, string> = {
        [SyncTrigger.Startup]: 'On startup',
        [SyncTrigger.Interval]: 'Scheduled',
        [SyncTrigger.Api]: 'Manual sync',
        [SyncTrigger.Webhook]: 'Webhook',
    }

    let error: string | undefined = $state()
    let gen = $state(0)
    let dryRunResult: DryRun | undefined = $state()

    async function loadLatest(): Promise<GitopsHistoryLatest> {
        return api.getGitopsHistoryLatest()
    }

    function load(opt: LoadOptions) {
        return from(
            api.getGitopsHistory({ offset: opt.offset, limit: opt.limit }),
        )
    }

    async function sync(forcePrune = false): Promise<void> {
        error = undefined
        try {
            const result = await api.syncGitops({
                syncGitopsRequest: { forcePrune },
            })
            if (
                !forcePrune &&
                result.status === SyncStatus.Failed &&
                result.plan?.some(c => c.action === PlanAction.Blocked)
            ) {
                if (
                    confirm(
                        'Syncing will delete more than a half of managed objects. Are you sure?',
                    )
                )
                    await sync(true)
            }
        } catch (err) {
            error = await stringifyError(err)
        }
        gen++
    }

    async function dryRun(): Promise<void> {
        error = undefined
        try {
            dryRunResult = await api.dryRunGitops({ syncGitopsRequest: {} })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    function summarizeDiff(
        row: ProviderSync,
    ): Partial<Record<PlanAction, number>> {
        const counts = new Map<PlanAction, number>()
        for (const { action } of row.plan ?? []) {
            if (action !== PlanAction.Unchanged) {
                counts.set(action, (counts.get(action) ?? 0) + 1)
            }
        }
        return Object.fromEntries(counts)
    }
</script>

<div class="page-summary-bar">
    <h1>gitops</h1>
    {#if $adminPermissions.configEdit}
        <div class="ms-auto d-flex align-items-center gap-3">
            <a class="btn btn-link" href="/config/gitops" use:link>
                Configure
            </a>
            <AsyncButton color="link" click={dryRun}>Dry run</AsyncButton>
            <AsyncButton color="primary" click={sync}>Sync now</AsyncButton>
        </div>
    {/if}
</div>

<GitopsDryRunModal bind:dryRun={dryRunResult} {sync} />

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#snippet entry(item: ProviderSync)}
    <div class="d-flex align-items-start gap-2">
        {#if item.status === SyncStatus.Failed}
            <Badge color="danger"> Failed </Badge>
        {:else if item.status === SyncStatus.Applied}
            <Badge color="success"> Applied </Badge>
        {:else if item.status === SyncStatus.Unchanged}
            <Badge color="secondary"> Unchanged </Badge>
        {/if}
        <div class="w-100">
            <div class="d-flex align-items-center gap-2">
                {#if item.revision}
                    <code>{item.revision.slice(0, 12)}</code>
                {/if}
                <span class="text-muted">{TRIGGERS[item.triggeredBy]}</span>
                <span class="ms-auto">
                    {const diff = summarizeDiff(item)}
                    {#if diff.create}
                        <Badge color="success"> +{diff.create} </Badge>
                    {/if}
                    {#if diff.update}
                        <Badge color="warning"> •{diff.update} </Badge>
                    {/if}
                    {#if diff.blocked}
                        <Badge color="danger"> &times;{diff.blocked} </Badge>
                    {/if}
                    {#if diff.delete}
                        <Badge color="danger"> –{diff.delete} </Badge>
                    {/if}
                </span>
                <span class="text-muted small">
                    <RelativeDate date={item.startedAt} />
                </span>
            </div>
            <div class="text-muted small">
                From {item.source}
                {#if item.checkedAt.valueOf() !== item.startedAt.valueOf()}
                    · last checked
                    <RelativeDate date={item.checkedAt} />
                {/if}
            </div>
            {#if item.error}
                <pre class="mt-1 mb-0">{item.error}</pre>
            {/if}
        </div>
    </div>
{/snippet}

{#key gen}
    <Loadable promise={loadLatest()}>
        {#snippet children(state)}
            {#if state.latest || state.latestSuccess}
                <h2>Current</h2>
            {/if}
            {#if state.latest}
                {@render entry(state.latest)}
                <div class="mb-4"></div>
            {/if}
            {#if state.latestSuccess && state.latestSuccess.id !== state.latest?.id}
                {@render entry(state.latestSuccess)}
                <div class="mb-4"></div>
            {/if}
        {/snippet}
    </Loadable>

    <h2>History</h2>
    <ItemList {load} pageSize={100}>
        {#snippet item(item)}
            <div class="list-group-item px-0">
                {@render entry(item)}
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
