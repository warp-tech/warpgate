<script lang="ts">
    import {
        faCircle as faCircleRegular,
        faUser,
    } from '@fortawesome/free-regular-svg-icons'
    import {
        faComputer,
        faPlay,
        faTimes,
    } from '@fortawesome/free-solid-svg-icons'
    import { Alert, Badge, Tooltip } from '@sveltestrap/sveltestrap'
    import {
        api,
        type Recording,
        type Target,
        type TargetSessionSnapshot,
        type UserSessionSnapshot,
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
    import { formatDistance } from 'date-fns'
    import { onDestroy } from 'svelte'
    import Fa from 'svelte-fa'
    import firstBy from 'thenby'
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
        session.targetSessions.sort(firstBy(x => x.started, 'desc'))
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

    function getRecordingsForSession(s: TargetSessionSnapshot) {
        return recordings?.filter(x => x.sessionId === s.id) ?? []
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
        </div>
        <div class="text-muted ms-auto">
            {#if session.ended}
                {formatDistance(new Date(session.started), new Date(session.ended))}
                long
            {/if}
            {#if session.nodeHostname}
                · on {session.nodeHostname}
            {/if}
        </div>
    </div>

    <div class="list-group list-group-flush tree">
        <div class="list-group-item">
            <Fa fw icon={faComputer} />
            <span class="text-muted">Connected from</span>
            <span>{session.remoteAddress}</span>
            <small class="text-muted ms-auto">
                <RelativeDate date={session.started} />
            </small>
        </div>

        <div class="list-group-item">
            <Fa fw icon={faUser} />
            {#if session.username}
                <span class="text-muted">Authenticated as</span>

                <Badge
                    href={$adminPermissions.usersEdit && session.userId ? `#/config/users/${session.userId}` : undefined}
                    color="success"
                    class="d-flex align-items-center"
                >
                    {#if session.username}
                        <Fa icon={faUser} class="me-2" />
                        {session.username}
                    {:else}
                        Logging in
                    {/if}
                </Badge>
            {:else}
                <span class="text-muted">
                    {#if session.ended}
                        Not authenticated
                    {:else}
                        Not authenticated yet
                    {/if}
                </span>
            {/if}
        </div>

        {#each session.targetSessions as targetSession (targetSession.id)}
            <div class="list-group-item">
                {#if targetSession.ended}
                    <Fa fw icon={faCircleRegular} />
                {:else}
                    <div class="blinking-live-icon">
                        <Fa fw icon={faCircleRegular} class="text-success" />
                    </div>
                {/if}
                <span class="text-muted">Connected to</span>
                {#if targetSession.target}
                    <Badge
                        href={$adminPermissions.targetsEdit && targetSession.targetId ? `#/config/targets/${targetSession.targetId}` : undefined}
                        color="info"
                        class="d-flex align-items-center"
                    >
                        <Fa icon={faComputer} class="me-2" />
                        {targetSession.target.name}
                    </Badge>
                {:else}
                    a now deleted target
                {/if}
                {#if targetSession.nodeHostname}
                    <small class="text-muted ms-auto">
                        via {targetSession.nodeHostname}
                    </small>
                {/if}
            </div>

            {#each getRecordingsForSession(targetSession) as recording (recording.id)}
                {@const metadata = JSON.parse(recording.metadata)}
                <div class="list-group-item">
                    <div class="indent">·</div>

                    {#if session.ended || recording.ended}
                        <Fa icon={faPlay} fw />
                    {:else}
                        <div class="blinking-live-icon">
                            <Fa icon={faPlay} fw class="text-warning" />
                        </div>
                    {/if}

                    <Badge
                        href={$adminPermissions.recordingsView ? `#/status/recordings/${recording.id}` : undefined}
                        color="warning"
                        class="d-flex align-items-center"
                    >
                        <Fa icon={recordingTypeIcon(recording)} class="me-2" />
                        {recordingTypeLabel(recording)}
                    </Badge>

                    <div class="meta-fields ms-2">
                        {#if metadata}
                            {#each recordingMetadataToFieldSet(metadata) as item (item[0])}
                                <small class="me-2">
                                    <span class="text-muted"> {item[0]}: </span>
                                    {item[1]}
                                </small>
                            {/each}
                        {/if}
                    </div>
                    <small class="text-muted ms-auto">
                        <RelativeDate date={recording.started} />
                    </small>
                </div>
            {/each}
        {/each}

        {#if session.ended && session.protocol !== 'HTTP'}
            <div class="list-group-item">
                <Fa fw icon={faTimes} />
                <span class="text-muted">Disconnected</span>
                <small class="text-muted ms-auto">
                    <RelativeDate date={session.ended} />
                </small>
            </div>
        {/if}
    </div>

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
.tree {
    .indent {
        width: 20px;
        text-align: center;
        opacity: .5;
    }

    .list-group-item {
        display: flex;
        align-items: center;
        gap: .5rem;
    }
}

.blinking-live-icon {
    animation: blinker 1s linear infinite;
}

@keyframes blinker {
    50% {
        opacity: .25;
    }
}
</style>
