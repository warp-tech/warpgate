<script lang="ts">
    import { faUser } from '@fortawesome/free-regular-svg-icons'
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Badge, Tooltip } from '@sveltestrap/sveltestrap'
    import {
        api,
        type Recording,
        type UserSessionSnapshot,
        type Target,
    } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import AsyncButton from 'common/AsyncButton.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { stringifyError } from 'common/errors'
    import { PROTOCOL_PROPERTIES } from 'common/protocols'
    import RelativeDate from 'common/RelativeDate.svelte'
    import {
        recordingMetadataToFieldSet,
        recordingTypeIcon,
        recordingTypeLabel,
    } from 'common/recordings'
    import StickyActionBar from 'common/StickyActionBar.svelte'
    import { formatDistance, formatDistanceToNow } from 'date-fns'
    import { onDestroy } from 'svelte'
    import Fa from 'svelte-fa'
    import { link } from 'svelte-spa-router'
    import LogViewer from '../log-viewer/LogViewer.svelte'

    interface Props {
        params: { id: string }
    }

    let { params = { id: '' } }: Props = $props()

    let error: string | null = $state(null)
    let session: UserSessionSnapshot | null = $state(null)
    let recordings: Recording[] | null = $state(null)

    async function load() {
        session = await api.getSession(params)
        recordings = await api.getSessionRecordings(params)
    }

    async function close() {
        if (!session) return
        api.closeSession(session)
    }

    function getTargetAddress(target: Target) {
        let address = '<unknown>'
        if (target.options.kind === 'Ssh') {
            address = `${target.options.host}:${target.options?.port}`
        }
        if (target.options.kind === 'MySql') {
            address = `${target.options.host}:${target.options?.port}`
        }
        if (target.options.kind === 'Postgres') {
            address = `${target.options.host}:${target.options?.port}`
        }
        if (target.options.kind === 'Http') {
            address = target.options.url
        }
        if (target.options.kind === 'Kubernetes') {
            address = target.options.clusterUrl
        }
        if (target.options.kind === 'Vnc') {
            address = `${target.options.host}:${target.options?.port}`
        }
        if (target.options.kind === 'Rdp') {
            address = `${target.options.host}:${target.options?.port}`
        }
        return address
    }

    load().catch(async e => {
        error = await stringifyError(e)
    })

    const interval = setInterval(load, 1000)
    onDestroy(() => clearInterval(interval))
</script>

{#if !session && !error}
    <DelayedSpinner />
{/if}

{#if error}
    <Alert color="danger">{error}</Alert>
{/if}

{#if session}
    <div class="page-summary-bar">
        <div class="flex-grow-1">
            <h1>{session.protocol} session</h1>
            <div class="d-flex align-items-center mt-1">
                <Tooltip delay="250" target="usernameBadge" animation>
                    Authenticated user
                </Tooltip>
                <Badge
                    href={$adminPermissions.usersEdit && session.userId ? `#/config/users/${session.userId}` : undefined}
                    id="usernameBadge"
                    color="success"
                    class="me-2 d-flex align-items-center"
                >
                    {#if session.username}
                        <Fa icon={faUser} class="me-2" />
                        {session.username}
                        {#if session.remoteAddress}
                            <span class="ms-1 ip">{session.remoteAddress}</span>
                        {/if}
                    {:else}
                        Logging in
                    {/if}
                </Badge>
            </div>
        </div>
        <div class="text-muted ms-auto">
            {#if session.ended}
                {formatDistance(new Date(session.started), new Date(session.ended))}
                long, <RelativeDate date={session.started} />
            {:else}
                {formatDistanceToNow(new Date(session.started))}
            {/if}
            {#if session.nodeHostname}
                · on {session.nodeHostname}
            {/if}
        </div>
    </div>

    <h3 class="mt-4">Connections</h3>
    {#if session.targetSessions.length}
        <div class="list-group">
            {#each session.targetSessions as targetSession (targetSession.id)}
                <div class="list-group-item d-flex align-items-center gap-3">
                    <span class:text-success={!targetSession.ended}>
                        {targetSession.ended ? 'Ended' : 'Active'}
                    </span>
                    {#if targetSession.target}
                        <Badge
                            href={$adminPermissions.targetsEdit && targetSession.targetId ? `#/config/targets/${targetSession.targetId}` : undefined}
                            color="info"
                            class="d-flex align-items-center"
                        >
                            <Fa icon={faArrowRight} class="me-2" />
                            {targetSession.target.name}
                            <span class="ms-1 ip">
                                {getTargetAddress(targetSession.target)}
                            </span>
                        </Badge>
                    {/if}
                    <small class="text-muted ms-auto">
                        {#if targetSession.ended}
                            {formatDistance(new Date(targetSession.started), new Date(targetSession.ended))}
                        {:else}
                            {formatDistanceToNow(new Date(targetSession.started))}
                        {/if}
                        {#if targetSession.nodeHostname}
                            · via {targetSession.nodeHostname}
                        {/if}
                    </small>
                </div>
            {/each}
        </div>
    {:else}
        <p class="text-muted">No target connections.</p>
    {/if}

    {#snippet recordingButton(recording: Recording)}
        {@const metadata = JSON.parse(recording.metadata)}
        <a
            class="btn"
            class:btn-secondary={recording.ended}
            class:btn-primary={!recording.ended}
            href="/status/recordings/{recording.id}"
            use:link
        >
            <Fa icon={recordingTypeIcon(recording)} fw size="lg" />
            <div class="flex-grow-1">
                <div>
                    <div class="d-flex align-items-center gap-1">
                        <strong>
                            {recordingTypeLabel(recording)}
                        </strong>
                    </div>
                    {#if metadata}
                        <div class="meta-fields">
                            {#each recordingMetadataToFieldSet(metadata) as item (item[0])}
                                <small>
                                    <span class="text-muted"> {item[0]}: </span>
                                    {item[1]}
                                </small>
                            {/each}
                        </div>
                    {/if}
                </div>
                <small class="meta">
                    <RelativeDate date={recording.started} />
                </small>
            </div>
        </a>
    {/snippet}

    {#if recordings?.find(x => !x.ended)}
        <h3 class="mt-4">Live view</h3>
        <div class="recordings-list">
            {#each recordings as recording (recording.id)}
                {#if !recording.ended}
                    {@render recordingButton(recording)}
                {/if}
            {/each}
        </div>
    {/if}

    {#if recordings?.find(x => x.ended)}
        <h3 class="mt-4">Recordings</h3>
        <div class="recordings-list">
            {#each recordings as recording (recording.id)}
                {#if recording.ended}
                    {@render recordingButton(recording)}
                {/if}
            {/each}
        </div>
    {/if}

    <h3 class="mt-4">Log</h3>
    <LogViewer
        filters={{
            sessionId: session.id,
        }}
    />

    {#if !session.ended && PROTOCOL_PROPERTIES[session.protocol]?.sessionsCanBeClosed}
        <StickyActionBar>
            <AsyncButton color="warning" click={close}>
                Close session now
            </AsyncButton>
        </StickyActionBar>
    {/if}
{/if}

<style lang="scss">
.recordings-list {
    display: flex;
    flex-wrap: wrap;
    gap: 2rem;

   .btn {
        display: flex;
        align-items: center;
        flex: 0.33 1 0;
        gap: 1.5rem;
        min-width: 300px;
        text-align: left;

        .meta {
            opacity: .75;
        }

        .meta-fields {
            display: flex;
            gap: 1rem;
        }
   }
}

.ip {
 opacity: .75;
}
</style>
