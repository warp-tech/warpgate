<script lang="ts">
    import {
        faPenToSquare,
        faTrashAlt,
    } from '@fortawesome/free-regular-svg-icons'
    import {
        faPlus,
        faSlash,
        faTriangleExclamation,
    } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Badge } from '@sveltestrap/sveltestrap'
    import {
        api,
        type DryRun,
        type GitopsHistoryLatest,
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
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { reloadServerInfo } from 'gateway/lib/store'
    import { from } from 'rxjs'
    import Fa, { FaLayers } from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import GitopsDryRunModal from './GitopsDryRunModal.svelte'

    const TRIGGERS: Record<SyncTrigger, string> = {
        [SyncTrigger.Startup]: 'On startup',
        [SyncTrigger.Interval]: 'Scheduled',
        [SyncTrigger.Api]: 'Manual sync',
        [SyncTrigger.Webhook]: 'Webhook',
        [SyncTrigger.Cli]: 'Command line',
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
            const outcome = await api.syncGitops({
                syncGitopsRequest: { forcePrune },
            })
            if (
                !forcePrune &&
                outcome.needsForce &&
                confirm(
                    `This sync would delete more than half (${outcome.stats?.guarded}) of all managed objects. Sync anyway?`,
                )
            ) {
                await sync(true)
            }
        } catch (err) {
            error = await stringifyError(err)
        }
        gen++
        await reloadServerInfo()
    }

    async function dryRun(): Promise<void> {
        error = undefined
        try {
            dryRunResult = await api.dryRunGitops({ syncGitopsRequest: {} })
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="page-summary-bar">
    <h1>gitops</h1>
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
                <span class="ms-auto d-flex align-items-center gap-2">
                    {#if item.stats}
                        {@const stats = item.stats}
                        {#if stats.create}
                            <Badge
                                color="success"
                                title="Objects added"
                                class="d-flex align-items-center gap-1"
                            >
                                <Fa icon={faPlus} />
                                {stats.create}
                            </Badge>
                        {/if}
                        {#if stats.update + stats.adopt}
                            <Badge
                                color="warning"
                                title="Objects updated or adopted"
                                class="d-flex align-items-center gap-1"
                            >
                                <Fa icon={faPenToSquare} />
                                {stats.update + stats.adopt}
                            </Badge>
                        {/if}
                        {#if stats.guarded}
                            <Badge
                                color="danger"
                                title="Deletions held back by the mass-deletion guard"
                                class="d-flex align-items-center gap-1"
                            >
                                <FaLayers>
                                    <Fa icon={faTrashAlt} />
                                    <Fa icon={faSlash} />
                                </FaLayers>
                                {stats.guarded}
                            </Badge>
                        {/if}
                        {#if stats.blocked + stats.collision}
                            <Badge
                                color="danger"
                                title="Objects that can't be changed; see the error"
                                class="d-flex align-items-center gap-1"
                            >
                                <Fa icon={faTriangleExclamation} />
                                {stats.blocked + stats.collision}
                            </Badge>
                        {/if}
                        {#if stats._delete}
                            <Badge
                                color="danger"
                                title="Objects deleted"
                                class="d-flex align-items-center gap-1"
                            >
                                <Fa icon={faTrashAlt} />
                                {stats._delete}
                            </Badge>
                        {/if}
                    {/if}
                </span>
            </div>
            <div class="d-flex align-items-center text-muted small">
                <div>From {item.source}</div>
                <div class="ms-auto">
                    <RelativeDate date={item.startedAt} />
                    {#if item.checkedAt.valueOf() !== item.startedAt.valueOf()}
                        · last checked
                        <RelativeDate date={item.checkedAt} />
                    {/if}
                </div>
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
                <h2>Current revision</h2>
            {/if}
            {#if state.latest}
                {@render entry(state.latest)}
                <div class="mb-4"></div>
            {/if}
            {#if state.latestSuccess &&
                state.latestSuccess.id !== state.latest?.id}
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

<StickyActionBar>
    {#snippet start()}
        {#if $adminPermissions.configEdit}
            <a class="btn btn-secondary me-auto" href="/config/gitops" use:link>
                Configure
            </a>
        {/if}
    {/snippet}
    {#snippet children()}
        {#if $adminPermissions.configEdit}
            <AsyncButton color="secondary" click={dryRun}>Dry run</AsyncButton>
            <AsyncButton color="primary" click={sync}>Sync now</AsyncButton>
        {/if}
    {/snippet}
</StickyActionBar>

<style>
    pre {
        white-space: pre-wrap;
    }
</style>
