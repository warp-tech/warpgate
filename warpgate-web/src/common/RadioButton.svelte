<script lang="ts" generics="T">
    import { Button, Input } from '@sveltestrap/sveltestrap'
    import { classnames } from './sveltestrap-s5-ports/_sveltestrapUtils'

    type Props = {
        group: T,
        value: T,
        label: string,
    } & Button['$$prop_def']

    let {
        group = $bindable(),
        value,
        label,
        ...rest
    }: Props = $props()

    let classes = $derived(classnames(
        'btn-radio-button',
        group === value ? 'active': false,
    ))
</script>

<Button on:click={e => {
    group = value
    e.preventDefault()
}} class={classes} {...rest}>
    <Input
        {label}
        type="radio"
        {value}
        bind:group={group}
        on:click={e => e.preventDefault()}
    />
</Button>


<style lang="scss">
    :global .btn-radio-button {
        text-align: left;

        label {
            margin-left: .75rem;
        }
    }
</style>
