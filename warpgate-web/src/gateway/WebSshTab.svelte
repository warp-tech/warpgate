<script lang="ts" module>
    export const THEME = {
        foreground: '#cacaca',
        background: '#171717',
        cursor: '#bbbbbb',
        colors: [
            '#000000',
            '#ff615a',
            '#b1e969',
            '#ebd99c',
            '#5da9f6',
            '#e86aff',
            '#82fff7',
            '#dedacf',
            '#313131',
            '#f58c80',
            '#ddf88f',
            '#eee5b2',
            '#a5c7ff',
            '#ddaaff',
            '#b7fff9',
            '#ffffff',
        ],
    }
</script>
<script lang="ts">
    import {
        Button,
        Modal,
        ModalBody,
        ModalFooter,
    } from '@sveltestrap/sveltestrap'
    import { FitAddon } from '@xterm/addon-fit'
    import { Unicode11Addon } from '@xterm/addon-unicode11'
    import { Terminal } from '@xterm/xterm'
    import { onDestroy } from 'svelte'
    import * as Zmodem from 'zmodem.js'

    enum ZmodemFeedResult {
        Consumed = 'consumed',
        Passthrough = 'passthrough',
    }

    interface ZmodemDetection {
        deny: () => void
        confirm: () => unknown
    }

    class ZmodemSession {
        // biome-ignore lint/suspicious/noExplicitAny: no types
        private sentry: any
        // biome-ignore lint/suspicious/noExplicitAny: no types
        private session: any = null
        private active = false

        confirmPending = $state(false)
        private confirmResolve: ((accepted: boolean) => void) | null = null

        constructor(
            private writeToTerminal: (data: Uint8Array) => void,
            private sendToHost: (data: Uint8Array) => void,
        ) {
            this.sentry = new Zmodem.Sentry({
                to_terminal: (octets: number[]) => {
                    if (this.active && this.session) {
                        this.writeToTerminal(Uint8Array.from(octets))
                    }
                },
                sender: (octets: number[]) => {
                    this.sendToHost(Uint8Array.from(octets))
                },
                on_detect: (detection: ZmodemDetection) => {
                    this.handleDetect(detection)
                },
                on_retract: () => {
                    this.session = null
                    this.active = false
                },
            })
        }

        feed(data: Uint8Array): ZmodemFeedResult {
            if (this.active || this.session) {
                try {
                    this.sentry.consume(data)
                } catch {
                    try {
                        this.session?.abort()
                    } catch {
                        // ignore
                    }
                    this.session = null
                    this.active = false
                }
                return ZmodemFeedResult.Consumed
            }

            try {
                this.sentry.consume(data)
            } catch {
                // Ignore detection errors when no session is active.
            }
            return ZmodemFeedResult.Passthrough
        }

        resolveConfirm(accepted: boolean): void {
            this.confirmPending = false
            this.confirmResolve?.(accepted)
            this.confirmResolve = null
        }

        destroy(): void {
            this.sentry.destroy?.()
        }

        private askConfirm(): Promise<boolean> {
            return new Promise(resolve => {
                this.confirmResolve = resolve
                this.confirmPending = true
            })
        }

        private async handleDetect(detection: ZmodemDetection): Promise<void> {
            const accepted = await this.askConfirm()
            if (!accepted) {
                detection.deny()
                return
            }

            this.active = true
            this.session = detection.confirm()

            try {
                if (this.session.type === 'send') {
                    await this.sendFile()
                } else {
                    // biome-ignore lint/suspicious/noExplicitAny: no types
                    this.session.on('offer', (xfer: any) => {
                        this.receiveFile(xfer).catch(() => {
                            try {
                                xfer.skip()
                            } catch {
                                // ignore
                            }
                        })
                    })
                    this.session.start()
                    await new Promise(resolve =>
                        this.session.on('session_end', resolve),
                    )
                }
            } catch {
                try {
                    this.session.abort()
                } catch {
                    //ignore
                }
            } finally {
                this.session = null
                this.active = false
            }
        }

        // biome-ignore lint/suspicious/noExplicitAny: no types
        private async receiveFile(xfer: any): Promise<void> {
            const chunks: Uint8Array[] = []
            await xfer.accept({
                on_input: (chunk: ArrayLike<number>) => {
                    chunks.push(Uint8Array.from(chunk))
                },
            })

            const { name } = xfer.get_details() as { name: string }
            const blob = new Blob(chunks as unknown as BlobPart[], {
                type: 'application/octet-stream',
            })

            const url = URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.href = url
            link.download = name
            document.body.appendChild(link)
            link.click()

            setTimeout(() => {
                document.body.removeChild(link)
                URL.revokeObjectURL(url)
            }, 100)
        }

        private async sendFile(): Promise<void> {
            const file = await new Promise<File | null>(resolve => {
                const input = document.createElement('input')
                input.type = 'file'
                input.multiple = false
                input.onchange = () => resolve(input.files?.[0] ?? null)
                input.click()
            })

            if (!file) {
                await this.session.close()
                return
            }

            const xfer = await this.session.send_offer({
                name: file.name,
                size: file.size,
                mode: 0o0666,
                mtime: Math.floor(file.lastModified / 1000),
            })

            if (xfer) {
                await xfer.send(new Uint8Array(await file.arrayBuffer()))
                await xfer.end()
            }

            await this.session.close()
        }
    }

    interface Props {
        active: boolean
        fontSize: number
        readOnly: boolean
        onInput: (data: Uint8Array) => void
        onResize: (cols: number, rows: number) => void
        onTitleChange: (title: string) => void
    }

    let {
        active,
        fontSize,
        readOnly,
        onInput,
        onResize,
        onTitleChange,
    }: Props = $props()

    const terminal = new Terminal({
        allowProposedApi: true,
        cursorBlink: true,
        theme: {
            foreground: THEME.foreground,
            background: THEME.background,
            cursor: THEME.cursor,
            black: THEME.colors[0],
            red: THEME.colors[1],
            green: THEME.colors[2],
            yellow: THEME.colors[3],
            blue: THEME.colors[4],
            magenta: THEME.colors[5],
            cyan: THEME.colors[6],
            white: THEME.colors[7],
            brightBlack: THEME.colors[8],
            brightRed: THEME.colors[9],
            brightGreen: THEME.colors[10],
            brightYellow: THEME.colors[11],
            brightBlue: THEME.colors[12],
            brightMagenta: THEME.colors[13],
            brightCyan: THEME.colors[14],
            brightWhite: THEME.colors[15],
        },
        fontFamily: 'monospace-fallback, monospace',
    })

    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)

    const inputEncoder = new TextEncoder()
    const zmodem = new ZmodemSession(
        data => terminal.write(data),
        data => onInput(data),
    )

    terminal.onData(data => {
        onInput(inputEncoder.encode(data))
    })
    terminal.onTitleChange(t => onTitleChange(t))
    terminal.loadAddon(new Unicode11Addon())
    terminal.unicode.activeVersion = '11'

    $effect(() => {
        terminal.options.fontSize = fontSize
        fitAddon.fit()
        onResize(terminal.cols, terminal.rows)
    })

    $effect(() => {
        terminal.options.disableStdin = readOnly
    })

    $effect(() => {
        if (!active) {
            return
        }
        requestAnimationFrame(() => {
            terminal.focus()
        })
    })

    export function write(data: Uint8Array): void {
        if (zmodem.feed(data) === ZmodemFeedResult.Passthrough) {
            terminal.write(data)
        }
    }

    export function fit(): void {
        fitAddon.fit()
        onResize(terminal.cols, terminal.rows)
    }

    export function getSize(): { cols: number; rows: number } {
        return { cols: terminal.cols, rows: terminal.rows }
    }

    function mountTerminal(el: HTMLDivElement) {
        terminal.open(el)
        requestAnimationFrame(() => {
            fitAddon.fit()
            onResize(terminal.cols, terminal.rows)
            if (active) {
                terminal.focus()
            }
        })
        return { destroy() {} }
    }

    onDestroy(() => {
        zmodem.destroy()
        terminal.dispose()
    })
</script>

<div
    class="position-absolute top-0 start-0 w-100 h-100"
    class:d-none={!active}
    use:mountTerminal
></div>

<Modal isOpen={zmodem.confirmPending} backdrop="static" keyboard={false}>
    <ModalBody>
        The remote side wants to start a ZMODEM file transfer. Accept?
    </ModalBody>
    <ModalFooter>
        <Button
            color="secondary"
            class="modal-button"
            onclick={() => zmodem.resolveConfirm(false)}
            >Reject</Button
        >
        <Button
            color="primary"
            class="modal-button"
            onclick={() => zmodem.resolveConfirm(true)}
            >Accept</Button
        >
    </ModalFooter>
</Modal>

<style lang="scss">
    @import "../../node_modules/@xterm/xterm/css/xterm.css";

    :global(.xterm) {
        height: 100%;
        padding: 7px 10px;
    }

    :global(.xterm-viewport) {
        overflow-y: hidden !important;
        background: transparent !important;
    }
</style>
