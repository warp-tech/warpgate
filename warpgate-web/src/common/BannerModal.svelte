<script lang="ts">
    // Acknowledgement is keyed by the banner text itself, so editing the banner
    // re-prompts everyone who already dismissed the old one.
    const STORAGE_KEY = 'warpgateBannerAcknowledged'

    const { banner }: { banner: string } = $props()

    let dialog: HTMLDialogElement | undefined = $state()
    let acknowledgedBanner = $state(localStorage[STORAGE_KEY] ?? '')
    const visible = $derived(!!banner.trim() && acknowledgedBanner !== banner)

    $effect(() => {
        if (visible) {
            dialog?.showModal()
        }
    })

    function acknowledge(): void {
        localStorage[STORAGE_KEY] = banner
        acknowledgedBanner = banner
    }
</script>

{#if visible}
    <dialog
        bind:this={dialog}
        class="warpgate-banner"
        oncancel={e => e.preventDefault()}
    >
        <p>{banner}</p>
        <button type="button" onclick={acknowledge}>Acknowledge</button>
    </dialog>
{/if}

<style lang="scss">
    dialog.warpgate-banner {
        max-width: 40rem;
        padding: 1.5rem;
        color: #eee;

        border-radius: 7px;
        border: 1px solid rgba(128, 128, 128, .25);
        background: #33333380;
        backdrop-filter: blur(4px);

        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;

        &::backdrop {
            background: rgba(0, 0, 0, .5);
        }

        p {
            margin: 0 0 1.5rem;
            white-space: pre-wrap;
        }

        button {
            appearance: none;
            -webkit-appearance: none;

            border: 1px solid rgba(128, 128, 128, .25);
            background: #33333380;
            backdrop-filter: blur(4px);
            padding: .5rem 1rem;
            border-radius: 6px;

            &:hover {
                color: #fafafa;
                background: #78787840;
            }
        }
    }
</style>
