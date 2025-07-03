<script lang="ts">
    import { api, type SessionSnapshot, type Recording, type TargetSSHOptions, type TargetHTTPOptions, type TargetMySqlOptions, type TargetPostgresOptions } from 'admin/lib/api'
    import { timeAgo } from 'admin/lib/time'
    import AsyncButton from 'common/AsyncButton.svelte'
    import DelayedSpinner from 'common/DelayedSpinner.svelte'
    import { formatDistance, formatDistanceToNow } from 'date-fns'
    import { onDestroy } from 'svelte'
    import { link } from 'svelte-spa-router'
    import LogViewer from './LogViewer.svelte'
    import RelativeDate from './RelativeDate.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import Fa from 'svelte-fa'
    import { faUser } from '@fortawesome/free-regular-svg-icons'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte'
    import { faArrowRight } from '@fortawesome/free-solid-svg-icons'
    import Tooltip from 'common/sveltestrap-s5-ports/Tooltip.svelte'

    interface Props {
        params: { id: string }
    }

    let { params = { id: '' } }: Props = $props()

    let error: string|null = $state(null)
    let session: SessionSnapshot|null = $state(null)
    let recordings: Recording[]|null = $state(null)

    async function load () {
        session = await api.getSession(params)
        recordings = await api.getSessionRecordings(params)
    }

    async function close () {
        api.closeSession(session!)
    }

    function getTargetDescription () {
        if (session?.target) {
            let address = '<unknown>'
            if (session.target.options.kind === 'Ssh') {
                const options = session.target.options as TargetSSHOptions
                address = `${options.host}:${options?.port}`
            }
            if (session.target.options.kind === 'MySql') {
                const options = session.target.options as TargetMySqlOptions
                address = `${options.host}:${options?.port}`
            }
            if (session.target.options.kind === 'Postgres') {
                const options = session.target.options as TargetPostgresOptions
                address = `${options.host}:${options?.port}`
            }
            if (session.target.options.kind === 'Http') {
                const options = session.target.options as unknown as TargetHTTPOptions
                address = options.url
            }
            return `${session.target.name} (${address})`
        } else {
            return 'Not selected yet'
        }
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
        <div>
            <h1>session</h1>
            <div class="d-flex align-items-center mt-1">
                <Tooltip delay="250" target="usernameBadge" animation>Authenticated user</Tooltip>
                <Tooltip delay="250" target="targetBadge" animation>Selected target</Tooltip>

                <Badge id="usernameBadge" color="success" class="me-2 d-flex align-items-center">
                    {#if session.username}
                        <Fa icon={faUser} class="me-2" />
                        {session.username}
                    {:else}
                        Logging in
                    {/if}
                </Badge>
                {#if session.target}
                    <Badge id="targetBadge" color="info" class="me-2 d-flex align-items-center">
                        <Fa icon={faArrowRight} class="me-2" />
                        {getTargetDescription()}
                    </Badge>
                {/if}
                <span class="text-muted">
                    {#if session.ended}
                        {formatDistance(new Date(session.started), new Date(session.ended))} long, <RelativeDate date={session.started} />
                    {:else}
                        {formatDistanceToNow(new Date(session.started))}
                    {/if}
                </span>
            </div>
        </div>
        {#if !session.ended}
            <div class="ms-auto">
                <AsyncButton color="warning" click={close}>
                    Close now
                </AsyncButton>
            </div>
        {/if}
    </div>

    {#if recordings?.length }
        <h3 class="mt-4">Recordings</h3>
        <div class="list-group list-group-flush">
            {#each recordings as recording (recording.id)}
                <a
                    class="list-group-item list-group-item-action"
                    href="/recordings/{recording.id}"
                    use:link>
                    <div class="main">
                        <strong>
                            {recording.name}
                        </strong>
                        <small class="meta ms-auto">
                            {timeAgo(recording.started)}
                        </small>
                    </div>
                </a>
            {/each}
        </div>
    {/if}

    <h3 class="mt-4">Log</h3>
    <LogViewer filters={{
        sessionId: session.id,
    }} />

{/if}

<style lang="scss">
.list-group-item {
    .main {
        display: flex;
        align-items: center;

        > * {
            margin-right: 20px;
        }
    }

    .meta {
        opacity: .75;
    }
}
</style>
