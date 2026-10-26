<script lang="ts">
    import InfoBox from 'common/InfoBox.svelte'
    import {
        type ReconnectingWebSocket,
        SocketState,
    } from 'gateway/lib/ReconnectingWebSocket.svelte'
    import {
        closeReasonText,
        type SessionPhase,
    } from 'gateway/lib/webClientSession'

    interface Props {
        phase: SessionPhase | null
        socket: ReconnectingWebSocket | undefined
        sessionNotFound: boolean
        // An HTTP-level failure or a non-fatal notice from the backend.
        notice: string | null
    }

    let { phase, socket, sessionNotFound, notice }: Props = $props()

    const text = $derived.by(() => {
        if (socket?.state === SocketState.Disconnected) {
            return 'Disconnected'
        }
        if (phase?.phase === 'awaiting_approval') {
            return 'Waiting for an administrator to approve this session…'
        }
        if (socket?.state === SocketState.Connecting && socket.attempt > 0) {
            return `Reconnecting (attempt ${socket.attempt})`
        }
        if (
            phase?.phase === 'connected' &&
            socket?.state === SocketState.Connected
        ) {
            return 'Connected'
        }
        return 'Connecting'
    })
</script>

{#if sessionNotFound}
    <InfoBox variant="warning" class="">
        Session not found. It may have expired or been closed.
    </InfoBox>
{:else if phase?.phase === 'closed'}
    <InfoBox variant="warning" class="">{closeReasonText(phase)}</InfoBox>
{:else if notice}
    <InfoBox variant="warning" class="">{notice}</InfoBox>
{:else}
    <span class="text-muted small">{text}</span>
{/if}
