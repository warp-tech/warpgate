<script lang="ts">
    import { Input } from '@sveltestrap/sveltestrap'

    type Props = {
        change?: CallableFunction
        value: number | undefined
    } & Input['$$prop_def']

    let { value = $bindable(), change, ...rest }: Props = $props()
</script>

<Input
    {...rest}
    type="number"
    min="0"
    step="1"
    bind:value={value}
    on:change={() => change?.()}
/>
