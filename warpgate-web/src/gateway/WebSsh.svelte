<script lang="ts">
    import {
        faGear,
        faMinus,
        faPlus,
        faTimes,
    } from '@fortawesome/free-solid-svg-icons'
    import {
        Button,
        Dropdown,
        DropdownItem,
        DropdownMenu,
        DropdownToggle,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import ConnectionInstructions from 'common/ConnectionInstructions.svelte'
    import InfoBox from 'common/InfoBox.svelte'
    import { reloadServerInfo, serverInfo } from 'gateway/lib/store'
    import { onDestroy, onMount, tick } from 'svelte'
    import { SvelteMap } from 'svelte/reactivity'
    import Fa from 'svelte-fa'
    import { loadTheme } from 'theme'
    import { api, ResponseError, type WebSshSessionInfo } from './lib/api'
    import {
        ConnectionState,
        ReconnectingWebSocket,
    } from './lib/ReconnectingWebSocket.svelte'
    import SshTerminalTab, { THEME } from './WebSshTab.svelte'

    interface Props {
        params: { sessionId: string }
    }
    let { params }: Props = $props()

    type ClientMessage =
        | { type: 'open_channel'; cols?: number; rows?: number }
        | { type: 'input'; channel_id: string; data: string }
        | { type: 'resize'; channel_id: string; cols: number; rows: number }
        | { type: 'close_channel'; channel_id: string }
        | { type: 'accept_host_key' }
        | { type: 'reject_host_key' }

    type ServerMessage =
        | { type: 'connection_state'; state: ConnectionState }
        | { type: 'output'; channel_id: string; data: string }
        | { type: 'channel_opened'; channel_id: string }
        | { type: 'channel_closed'; channel_id: string }
        | { type: 'eof'; channel_id: string }
        | { type: 'exit_status'; channel_id: string; code: number }
        | { type: 'error'; message: string }
        | {
              type: 'host_key_unknown'
              host: string
              port: number
              key_type: string
              key_base64: string
          }

    interface ChannelState {
        id: string
        label: string
        terminalTitle: string | undefined
        closed: boolean
    }

    let channels = new SvelteMap<string, ChannelState>()
    let channelOrder: string[] = $state([])
    let activeChannelId: string | null = $state(null)
    let connectionError: string | null = $state(null)
    let sessionNotFound = $state(false)
    let pendingHostKey: Extract<
        ServerMessage,
        { type: 'host_key_unknown' }
    > | null = $state(null)
    const tabs: Record<string, SshTerminalTab> = {}

    // svelte-ignore state_referenced_locally
    const { sessionId } = params

    let sessionInfo = $state<WebSshSessionInfo | null>(null)

    const FONT_SIZE_MIN = 8
    const FONT_SIZE_MAX = 32
    const FONT_SIZE_STEP = 1
    let fontSize = $state(
        parseInt(localStorage.warpgateWebSSHFontSize ?? '14', 10),
    )

    $effect(() => {
        localStorage.warpgateWebSSHFontSize = String(fontSize)
    })

    function zoomIn() {
        fontSize = Math.min(FONT_SIZE_MAX, fontSize + FONT_SIZE_STEP)
    }
    function zoomOut() {
        fontSize = Math.max(FONT_SIZE_MIN, fontSize - FONT_SIZE_STEP)
    }

    let menuOpen = $state(false)
    let showInstructions = $state(false)

    const ws = new ReconnectingWebSocket({
        url: `wss://${location.host}/@warpgate/api/web-ssh/sessions/${sessionId}/stream`,
        onOpen: () => {
            if (channelOrder.length === 0) {
                requestNewChannel()
            }
        },
        onMessage: data =>
            onMessage(JSON.parse(data as string) as ServerMessage),
    })

    function send(msg: ClientMessage) {
        ws.send(JSON.stringify(msg))
    }

    function bytesToBase64(bytes: Uint8Array): string {
        let binary = ''
        const chunkSize = 0x8000
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, i + chunkSize)
            binary += String.fromCharCode(...chunk)
        }
        return btoa(binary)
    }

    function requestNewChannel() {
        const size = activeChannelId ? tabs[activeChannelId]?.getSize() : null
        send({
            type: 'open_channel',
            cols: size?.cols ?? 80,
            rows: size?.rows ?? 24,
        })
    }

    function onMessage(msg: ServerMessage) {
        switch (msg.type) {
            case 'connection_state':
                ws.state = msg.state
                break
            case 'channel_opened':
                openChannel(msg.channel_id)
                break
            case 'output':
                tabs[msg.channel_id]?.write(
                    Uint8Array.from(atob(msg.data), c => c.charCodeAt(0)),
                )
                break
            case 'channel_closed':
            case 'eof': {
                const ch = channels.get(msg.channel_id)
                if (ch) {
                    ch.closed = true
                }
                break
            }
            case 'exit_status': {
                const ch = channels.get(msg.channel_id)
                if (ch) {
                    tabs[msg.channel_id]?.write(
                        Uint8Array.from(
                            `\r\n[Process exited with code ${msg.code}]\r\n`,
                            c => c.charCodeAt(0),
                        ),
                    )
                }
                break
            }
            case 'error':
                ws.state = ConnectionState.Error
                connectionError = msg.message
                break
            case 'host_key_unknown':
                pendingHostKey = msg
                break
        }
    }

    function openChannel(id: string) {
        channels.set(id, {
            id,
            label: `Shell ${channelOrder.length + 1}`,
            terminalTitle: undefined,
            closed: false,
        })
        channelOrder = [...channelOrder, id]
        activeChannelId = id
    }

    async function switchToChannel(id: string) {
        activeChannelId = id
        // wait until visible
        await tick()
        requestAnimationFrame(() => {
            tabs[id]?.fit()
        })
    }

    function closeTab(id: string) {
        send({ type: 'close_channel', channel_id: id })
        channels.delete(id)
        channelOrder = channelOrder.filter(x => x !== id)
        if (activeChannelId === id) {
            activeChannelId = channelOrder[channelOrder.length - 1] ?? null
        }
    }

    function observeResize(node: HTMLElement) {
        const resizeObserver = new ResizeObserver(() => {
            if (activeChannelId) {
                tabs[activeChannelId]?.fit()
            }
        })
        resizeObserver.observe(node)
        return {
            destroy() {
                resizeObserver.disconnect()
            },
        }
    }

    async function disconnect() {
        ws.close()
        await api.deleteWebSshSession({ sessionId })
        window.close()
    }

    onMount(async () => {
        reloadServerInfo()

        try {
            sessionInfo = await api.getWebSshSession({ sessionId })
        } catch (e) {
            connectionError =
                e instanceof Error ? e.message : 'Failed to load session info'
            if (e instanceof ResponseError && e.response.status === 404) {
                sessionNotFound = true
            }
            return
        }
        ws.connect()
    })

    const originalTitle = document.title
    const windowTitle = $derived.by(() => {
        const activeTerminalTitle = activeChannelId
            ? channels.get(activeChannelId)?.terminalTitle
            : undefined
        const baseTitle = activeTerminalTitle ?? originalTitle
        const targetName = sessionInfo?.targetName
        return targetName ? `${targetName} - ${baseTitle}` : baseTitle
    })
    $effect(() => {
        document.title = windowTitle
    })

    onDestroy(() => {
        ws.close()
    })

    loadTheme('dark')
</script>

<div
    class="ssh-web-client d-flex flex-column"
    use:observeResize
    style={`background-color: ${THEME.background}`}
>
    <div class="terminal-area flex-grow-1 position-relative">
        {#each channelOrder as id (id)}
            {@const channel = channels.get(id)}
            {#if channel}
                <SshTerminalTab
                    bind:this={tabs[id]}
                    active={id === activeChannelId}
                    {fontSize}
                    readOnly={ws.state !== ConnectionState.Connected}
                    onInput={data => send({ type: 'input', channel_id: id, data: bytesToBase64(data) })}
                    onResize={(cols, rows) => send({ type: 'resize', channel_id: id, cols, rows })}
                    onTitleChange={title => {
                        channels.set(id, {
                            ...channel,
                            terminalTitle: title,
                        })
                    }}
                />
            {/if}
        {/each}
    </div>

    {#if connectionError}
        <div class="mx-3 mt-3">
            <InfoBox variant="warning">
                {#if sessionNotFound}
                    Session not found. It may have expired or been closed.
                {:else}
                    {connectionError}
                {/if}
            </InfoBox>
        </div>
    {:else}
        <div class="toolbar d-flex align-items-center gap-2 p-2">
            <div class="tab-bar d-flex align-items-stretch gap-2 flex-grow-1">
                {#each channelOrder as id (id)}
                    {@const ch = channels.get(id)}
                    {#if ch}
                        <!-- biome-ignore lint/a11y/useSemanticElements: nested -->
                        <div
                            class="tab btn btn-secondary d-flex align-items-center"
                            class:active={id === activeChannelId}
                            tabindex="0"
                            role="button"
                            onclick={() => switchToChannel(id)}
                            onkeydown={e => e.key === 'Enter' && switchToChannel(id)}
                        >
                            <span class="label"
                                >{ch.terminalTitle ?? ch.label}</span
                            >
                            <button
                                type="button"
                                class="btn btn-link btn-sm close-button"
                                onclick={e => { e.stopPropagation(); closeTab(id) }}
                            >
                                <Fa icon={faTimes} />
                            </button>
                        </div>
                    {/if}
                {/each}

                {#if ws.state === ConnectionState.Connected}
                    <button
                        type="button"
                        class="btn btn-secondary px-3"
                        onclick={requestNewChannel}
                    >
                        <Fa icon={faPlus} />
                    </button>
                {/if}
            </div>

            {#if !sessionNotFound}
                <span class="text-muted small me-3">
                    {ws.state}
                    {#if ws.state === ConnectionState.Connecting && ws.attempt > 0}
                        &nbsp;(attempt {ws.attempt})
                    {/if}
                </span>
            {/if}

            {#if ws.state === ConnectionState.Connected}
                <Button color="danger" onclick={disconnect}>Disconnect</Button>
            {/if}

            <Dropdown bind:isOpen={menuOpen}>
                <DropdownToggle color="secondary" caret={false}>
                    <Fa icon={faGear} />
                </DropdownToggle>
                <DropdownMenu end>
                    <div
                        class="dropdown-item disabled font-size-row d-flex align-items-center gap-2"
                    >
                        <button
                            type="button"
                            class="btn btn-sm btn-secondary"
                            disabled={fontSize <= FONT_SIZE_MIN}
                            onclick={() => { zoomOut(); menuOpen = true }}
                            aria-label="Zoom out"
                        >
                            <Fa icon={faMinus} />
                        </button>
                        <span class="text-nowrap ms-auto me-auto"
                            >{fontSize}px</span
                        >
                        <button
                            type="button"
                            class="btn btn-sm btn-secondary"
                            disabled={fontSize >= FONT_SIZE_MAX}
                            onclick={() => { zoomIn(); menuOpen = true }}
                            aria-label="Zoom in"
                        >
                            <Fa icon={faPlus} />
                        </button>
                    </div>
                    {#if sessionInfo}
                        <DropdownItem divider />
                        <DropdownItem
                            onclick={() => { showInstructions = true; menuOpen = false }}
                        >
                            Connect from your machine
                        </DropdownItem>
                    {/if}
                </DropdownMenu>
            </Dropdown>
        </div>
    {/if}
</div>

{#if sessionInfo}
    <Modal
        isOpen={showInstructions}
        toggle={() => showInstructions = false}
        size="lg"
    >
        <ModalBody>
            <ConnectionInstructions
                targetName={sessionInfo.targetName}
                targetKind={sessionInfo.targetKind}
                username={$serverInfo?.username}
            />
        </ModalBody>
        <ModalFooter>
            <Button
                color="secondary"
                class="modal-button"
                onclick={() => showInstructions = false}
                >Close</Button
            >
        </ModalFooter>
    </Modal>
{/if}

{#if pendingHostKey}
    <Modal isOpen={true} backdrop="static" keyboard={false}>
        <ModalBody>
            <div class="mb-3">
                There is currently no trusted {pendingHostKey.key_type} key for
                the SSH server at {pendingHostKey.host}:{pendingHostKey.port}.
                Trust this key?
            </div>
            <code>{pendingHostKey.key_type} {pendingHostKey.key_base64}</code>
        </ModalBody>
        <ModalFooter>
            <Button
                color="danger"
                class="modal-button"
                onclick={() => {
                send({ type: 'reject_host_key' })
                pendingHostKey = null
                disconnect()
            }}
                >Reject and disconnect</Button
            >
            <Button
                color="primary"
                class="modal-button"
                onclick={() => {
                send({ type: 'accept_host_key' })
                pendingHostKey = null
            }}
                >Accept and connect</Button
            >
        </ModalFooter>
    </Modal>
{/if}

<style lang="scss">
    :global(body) {
        margin: 0;
        overflow: hidden;
    }

    .ssh-web-client {
        height: 100vh;
    }

    .toolbar {
        flex-shrink: 0;
        margin: 10px;
        background: black;
        border-radius: 10px;
    }

    .tab-bar {
        overflow-x: auto;
    }

    .terminal-area {
        overflow: hidden;
    }

    .tab {
        padding: 0;

        .label {
            margin: 0.25rem 0 0.25rem 1rem;
        }

        .close-button {
            margin-left: 0.5rem;
        }
    }

    .font-size-row {
        padding: 0.25rem 1rem;
        min-width: 220px;
        pointer-events: none;

        button {
            pointer-events: initial;
        }
    }

</style>
