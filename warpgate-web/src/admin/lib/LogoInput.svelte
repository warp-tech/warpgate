<script lang="ts">
    import { Button } from '@sveltestrap/sveltestrap'
    import HelpText from 'admin/lib/HelpText.svelte'
    import { logoUrl, uuid } from 'common/helpers'

    const id = uuid()

    interface Props {
        etag?: string | null
        /**
         * Pending edit: undefined keeps the stored logo, null removes it and a
         * data URL replaces it.
         */
        value?: string | null
    }

    let { etag, value = $bindable() }: Props = $props()

    let error: string | undefined = $state()
    let input: HTMLInputElement | undefined = $state()

    const preview = $derived(
        value ?? (value === undefined && etag ? logoUrl(etag) : undefined),
    )

    async function load(file: File) {
        const dataUrl = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader()
            reader.onload = () => resolve(reader.result as string)
            reader.onerror = () => reject(reader.error)
            reader.readAsDataURL(file)
        })
        if (
            !/^data:image\/(png|jpeg|gif|webp|svg\+xml);base64,/.test(dataUrl)
        ) {
            error = 'Unsupported image type'
        } else if (dataUrl.length > 4 * 1024 * 1024) {
            error = 'Image too large, keep it under 4 MB'
        } else {
            error = undefined
            value = dataUrl
        }
    }

    function remove() {
        value = null
        if (input) {
            input.value = ''
        }
    }
</script>

<div class="d-flex align-items-center gap-3 mb-2">
    {#if preview}
        <img
            src={preview}
            alt="Logo"
            class="d-block me-auto"
            style="height: 32px"
        >
    {:else}
        <div class="text-muted me-auto">No image selected</div>
    {/if}
    <input
        id="logoInput-{id}-input"
        bind:this={input}
        type="file"
        class="d-none"
        accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml"
        onchange={e => {
            const file = e.currentTarget.files?.[0]
            if (file) {
                load(file)
            }
        }}
    >
    <label class="btn btn-secondary" for="logoInput-{id}-input">
        {#if preview}
            Change
        {:else}
            Choose
        {/if}
    </label>
    {#if preview}
        <Button
            type="button"
            color="danger"
            class="text-nowrap"
            onclick={remove}
        >
            Clear
        </Button>
    {/if}
</div>
{#if error}
    <div class="text-danger mt-2">{error}</div>
{/if}
<HelpText>
    Replaces the Warpgate logo in the header and on the login page. PNG, JPEG,
    GIF, WebP or SVG up to 4 MB.
</HelpText>
