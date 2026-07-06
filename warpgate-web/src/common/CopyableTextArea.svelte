<script lang="ts">
    import { FormGroup } from '@sveltestrap/sveltestrap'
    import CopyButton from './CopyButton.svelte'
    import { classnames } from './helpers'

    interface Props {
        label: string
        value: string
        class?: string
    }

    let { label, value, class: className = '' }: Props = $props()
</script>

<FormGroup floating {label} class="copyable-textarea">
    <div class={classnames(className, 'form-control', 'text')}>{value}</div>
    <CopyButton class="copy-button btn-sm" text={value} />
</FormGroup>

<style lang="scss">
    .text {
        font-family: var(--bs-font-monospace);
        font-size: 0.9em;

        white-space: pre-wrap;
        overflow: hidden;
        word-wrap: break-word;
        height: auto;

        padding-top: 35px !important; // clear the copy button
    }

    :global(.copyable-textarea) {
        position: relative;

        :global(.copy-button) {
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            z-index: 1;
        }
    }
</style>
