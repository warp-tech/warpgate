<script lang="ts">
    /**
     * Phase 2 styleguide: one entry per primitive, each showing the states
     * that actually break in production — hover, focus, disabled, loading and
     * error — rather than only the happy path.
     */
    import { of } from 'rxjs'
    import Badge from 'ui/Badge.svelte'
    import Button from 'ui/Button.svelte'
    import Checkbox from 'ui/Checkbox.svelte'
    import Chip from 'ui/Chip.svelte'
    import Drawer from 'ui/Drawer.svelte'
    import EmptyState from 'ui/EmptyState.svelte'
    import Input from 'ui/Input.svelte'
    import Modal from 'ui/Modal.svelte'
    import SegmentedControl from 'ui/SegmentedControl.svelte'
    import Select from 'ui/Select.svelte'
    import SkeletonRow from 'ui/SkeletonRow.svelte'
    import Spinner from 'ui/Spinner.svelte'
    import StatusMarker, {
        STATUS,
        type StatusKind,
    } from 'ui/StatusMarker.svelte'
    import Table from 'ui/Table.svelte'
    import Tabs from 'ui/Tabs.svelte'
    import Toggle from 'ui/Toggle.svelte'
    import TokenInput from 'ui/TokenInput.svelte'
    import Tooltip from 'ui/Tooltip.svelte'
    import { toast } from 'ui/toasts.svelte'
    import AuditTable, { type AuditTarget } from './AuditTable.svelte'

    // ---- demo state -------------------------------------------------------
    let text = $state('prod-bastion-01')
    let empty = $state('')
    let selectValue: string = $state('ssh')
    let checked = $state(true)
    let indeterminate = $state(true)
    let toggleOn = $state(true)
    let density: 'comfortable' | 'dense' = $state('comfortable')
    let tab: string = $state('overview')
    let tokens = $state(['10.0.0.0/8', '192.168.1.0/24'])
    let filterOn = $state(true)
    let modalOpen = $state(false)
    let drawerOpen = $state(false)
    let selectedRows: string[] = $state([])

    const PROTOCOLS = [
        { value: 'ssh', label: 'SSH' },
        { value: 'http', label: 'HTTP' },
        { value: 'mysql', label: 'MySQL' },
        { value: 'rdp', label: 'RDP (unavailable)', disabled: true },
    ]

    const DEMO_ROWS = [
        {
            id: 's1',
            user: 'marta.kowalski',
            target: 'prod-bastion-01',
            proto: 'SSH',
            status: 'live' as StatusKind,
        },
        {
            id: 's2',
            user: 'j.okafor',
            target: 'analytics-ro',
            proto: 'MySQL',
            status: 'ended' as StatusKind,
        },
        {
            id: 's3',
            user: 'svc-backup',
            target: 'core-redis',
            proto: 'SSH',
            status: 'failed' as StatusKind,
        },
        {
            id: 's4',
            user: 'l.zhang',
            target: 'win-diag-02',
            proto: 'RDP',
            status: 'pending' as StatusKind,
        },
    ]

    const columns = [
        { key: 'status', label: 'Status', width: '9rem' },
        { key: 'user', label: 'User', sortable: true },
        { key: 'target', label: 'Target', sortable: true },
        { key: 'proto', label: 'Protocol' },
    ]

    function loadDemo() {
        return of({ items: DEMO_ROWS, offset: 0, total: DEMO_ROWS.length })
    }

    async function slowOk() {
        await new Promise(r => setTimeout(r, 1400))
    }

    async function slowFail() {
        await new Promise(r => setTimeout(r, 1200))
        throw new Error('Connection refused')
    }

    function validateCidr(token: string): string | null {
        return /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(token)
            ? null
            : `"${token}" is not an IPv4 address or CIDR range`
    }

    const AUDITS: AuditTarget[] = [
        { name: 'Button / primary', selector: '#a-btn-primary' },
        { name: 'Button / secondary', selector: '#a-btn-secondary' },
        { name: 'Button / destructive', selector: '#a-btn-destructive' },
        {
            name: 'Button / destructive border',
            selector: '#a-btn-destructive',
            rule: 'ui',
            border: true,
        },
        { name: 'Button / ghost', selector: '#a-btn-ghost' },
        { name: 'Badge / danger', selector: '#a-badge-danger' },
        { name: 'Badge / warning', selector: '#a-badge-warning' },
        { name: 'Badge / success', selector: '#a-badge-success' },
        { name: 'Chip / selected', selector: '#a-chip-selected' },
        {
            name: 'Input border',
            selector: '#a-input-shell-wrap .wg-input-shell',
            rule: 'ui',
            border: true,
        },
        {
            name: 'Input error text',
            selector: '#a-input-error-wrap .wg-field-error',
        },
        { name: 'Table header', selector: '.wg-table thead th' },
        { name: 'Table cell', selector: '.wg-table tbody td' },
        { name: 'Tab / active', selector: '.wg-tab-active' },
        {
            name: 'Toggle track (on)',
            selector: '#a-toggle',
            rule: 'ui',
            border: true,
        },
    ]

    const ALL_STATUSES = Object.keys(STATUS) as StatusKind[]
</script>

<!-- ══ Button ══════════════════════════════════════════════════════ -->
<section>
    <h2>Button</h2>
    <p class="note">
        Four variants. The async state machine is lifted verbatim from
        <code>common/AsyncButton.svelte</code>
        — 500ms before a spinner appears, 1000ms holding the outcome, width and
        height pinned from the pre-click measurements so the row does not reflow
        under the pointer.
        <strong>Press the two loading buttons</strong>
        to watch it.
    </p>

    <div class="row">
        <Button id="a-btn-primary" variant="primary">Save changes</Button>
        <Button id="a-btn-secondary" variant="secondary">Cancel</Button>
        <Button id="a-btn-destructive" variant="destructive"
            >Close session</Button
        >
        <Button id="a-btn-ghost" variant="ghost">More</Button>
    </div>

    <p class="label">Compact</p>
    <div class="row">
        <Button variant="primary" size="compact">Save</Button>
        <Button variant="secondary" size="compact">Cancel</Button>
        <Button variant="destructive" size="compact">Revoke</Button>
    </div>

    <p class="label">Disabled</p>
    <div class="row">
        <Button variant="primary" disabled>Save changes</Button>
        <Button variant="secondary" disabled>Cancel</Button>
        <Button variant="destructive" disabled>Close session</Button>
    </div>

    <p class="label">Loading → done, and loading → failed</p>
    <div class="row">
        <Button variant="primary" click={slowOk}>Succeeds after 1.4s</Button>
        <Button
            variant="destructive"
            click={async () => {
                try {
                    await slowFail()
                } catch {
                    /* swallowed here so the styleguide does not error-boundary */
                }
            }}
        >
            Fails after 1.2s
        </Button>
        <Spinner label="Standalone spinner" />
    </div>
</section>

<!-- ══ StatusMarker ════════════════════════════════════════════════ -->
<section>
    <h2>StatusMarker</h2>
    <p class="note">
        The status convention for every table.
        <strong>There is no colour prop and no shape prop</strong>
        — a call site picks a <code>kind</code> and the geometry comes with it,
        so a screen cannot express "red" without also expressing a shape and a
        label. Adding a state means adding a row to the frozen map in the
        component, which is the review point.
    </p>
    <div class="row">
        {#each ALL_STATUSES as kind (kind)}
            <StatusMarker {kind} />
        {/each}
    </div>

    <p class="label">With a real timestamp, and bare for dense cells</p>
    <div class="row">
        <StatusMarker kind="ended" label="Ended 12:04:31" />
        <StatusMarker kind="live" bare />
        <StatusMarker kind="blocked" bare label="Blocked — 3 attempts" />
    </div>
</section>

<!-- ══ Badge & Chip ════════════════════════════════════════════════ -->
<section>
    <h2>Badge</h2>
    <p class="note">
        Read-only label. Accents sit on the border and text, never the fill — a
        row of filled badges turns a table into a colour chart.
    </p>
    <div class="row">
        <Badge>Default</Badge>
        <Badge tone="primary">Primary</Badge>
        <Badge id="a-badge-success" tone="success">Verified</Badge>
        <Badge id="a-badge-warning" tone="warning">Expiring</Badge>
        <Badge id="a-badge-danger" tone="danger">Revoked</Badge>
        <Badge mono>SHA256:qF3nP8xK</Badge>
    </div>
</section>

<section>
    <h2>Chip <span class="new">net-new</span></h2>
    <p class="note">
        Interactive counterpart to Badge: a removable or selectable token.
        Removable and selectable are mutually exclusive in the type — a chip
        that is both has two conflicting click targets. The remove button names
        what it removes, not just "Remove".
    </p>
    <div class="row">
        <Chip onRemove={() => {}}>admin</Chip>
        <Chip mono onRemove={() => {}}>10.0.0.0/8</Chip>
        <Chip onRemove={() => {}} disabled>locked</Chip>
    </div>
    <p class="label">Selectable (filter chips)</p>
    <div class="row">
        <Chip
            id="a-chip-selected"
            onSelect={() => (filterOn = !filterOn)}
            selected={filterOn}
        >
            SSH only
        </Chip>
        <Chip onSelect={() => {}} selected={false}>Failed only</Chip>
        <Chip onSelect={() => {}} disabled>Archived</Chip>
    </div>
</section>

<!-- ══ Input / Select ══════════════════════════════════════════════ -->
<section>
    <h2>Input</h2>
    <p class="note">
        Errors are wired through <code>aria-describedby</code>, and passing
        <code>error</code>
        implies the invalid state so the two cannot drift apart. The border is
        <code>border-strong</code>
        per the border rule.
    </p>
    <div class="grid">
        <div id="a-input-shell-wrap">
            <Input label="Target name" bind:value={text} />
        </div>
        <Input label="Hostname" mono value="10.12.4.8" hint="IPv4 or FQDN" />
        <Input
            label="Search"
            type="search"
            placeholder="Search…"
            bind:value={empty}
        />
        <Input label="Disabled" value="unchangeable" disabled />
        <Input label="Read-only" value="system-generated" readonly />
        <div id="a-input-error-wrap">
            <Input
                label="Port"
                value="70000"
                error="Port must be between 1 and 65535"
            />
        </div>
        <Input label="Required" value="" required hint="Cannot be blank" />
        <Input label="Compact" size="compact" value="dense toolbar" />
    </div>
</section>

<section>
    <h2>Select</h2>
    <div class="grid">
        <Select label="Protocol" options={PROTOCOLS} bind:value={selectValue} />
        <Select
            label="With placeholder"
            options={PROTOCOLS}
            placeholder="Choose a protocol…"
        />
        <Select label="Disabled" options={PROTOCOLS} value="ssh" disabled />
        <Select
            label="Invalid"
            options={PROTOCOLS}
            value="ssh"
            error="This protocol is not enabled on the gateway"
        />
    </div>
</section>

<!-- ══ Checkbox / Toggle ═══════════════════════════════════════════ -->
<section>
    <h2>Checkbox</h2>
    <p class="note">
        The native input keeps every built-in behaviour — focus, form
        participation, Space to toggle — and is made transparent over a styled
        box, rather than replaced. <code>indeterminate</code> is a DOM property
        with no attribute, so it is assigned in an effect.
    </p>
    <div class="row">
        <Checkbox label="Record this session" bind:checked />
        <Checkbox
            label="Partially selected"
            bind:indeterminate
            checked={false}
        />
        <Checkbox label="Unchecked" checked={false} />
        <Checkbox label="Disabled" checked disabled />
    </div>
    <div style="margin-top: var(--wg-space-md)">
        <Checkbox
            label="Allow ticket self-service"
            checked
            hint="Users can request their own access tickets from the portal"
        />
    </div>
</section>

<section>
    <h2>Toggle <span class="new">net-new</span></h2>
    <p class="note">
        <code>role="switch"</code>, not a restyled checkbox. A checkbox says
        "this will be true when you save"; a switch says "this is on now".
        Warpgate's settings are mostly the latter.
    </p>
    <div class="col">
        <Toggle id="a-toggle" label="Target enabled" bind:checked={toggleOn} />
        <Toggle label="Off" checked={false} />
        <Toggle label="Disabled, on" checked disabled />
        <Toggle
            label="Require approval"
            checked={false}
            hint="Every connection waits for an administrator"
        />
        <Toggle label="Compact" size="compact" checked />
    </div>
</section>

<!-- ══ TokenInput ══════════════════════════════════════════════════ -->
<section>
    <h2>TokenInput <span class="new">net-new</span></h2>
    <p class="note">
        Commits text into discrete tokens. Enter or comma commits, Backspace on
        an empty field removes the last, Escape clears the draft, and paste
        splits on commas, semicolons, tabs and newlines so a list copied from a
        config file lands as tokens. Blur commits rather than discards — a
        typed-but-uncommitted value silently vanishing at save time is the bug
        this pattern usually ships with.
        <strong>Try pasting</strong> <code>172.16.0.0/12, 10.1.2.3</code>.
    </p>
    <div class="grid">
        <TokenInput
            label="Allowed IP ranges"
            bind:tokens
            placeholder="Add a CIDR range…"
            validate={validateCidr}
        />
        <TokenInput
            label="Disabled"
            tokens={['role:admin', 'role:auditor']}
            disabled
        />
    </div>
</section>

<!-- ══ SegmentedControl / Tabs ═════════════════════════════════════ -->
<section>
    <h2>SegmentedControl <span class="new">net-new</span></h2>
    <p class="note">
        Picks a value; it does not swap a panel. Built on real radio inputs, so
        arrow-key traversal and the single-tab-stop behaviour come from the
        platform rather than from hand-rolled key handlers.
    </p>
    <div class="col">
        <SegmentedControl
            label="Row density"
            labelHidden={false}
            bind:value={density}
            segments={[
                { value: 'comfortable', label: 'Comfortable' },
                { value: 'dense', label: 'Dense' },
            ]}
        />
        <SegmentedControl
            label="Playback speed"
            labelHidden={false}
            value="1"
            segments={[
                { value: '0.5', label: '0.5×' },
                { value: '1', label: '1×' },
                { value: '2', label: '2×' },
                { value: '4', label: '4× (unavailable)', disabled: true },
            ]}
        />
        <SegmentedControl
            label="Disabled group"
            labelHidden={false}
            value="a"
            disabled
            segments={[
                { value: 'a', label: 'One' },
                { value: 'b', label: 'Two' },
            ]}
        />
    </div>
</section>

<section>
    <h2>Tabs <span class="new">net-new</span></h2>
    <p class="note">
        A real ARIA tablist — it swaps a panel. Roving tabindex, Arrow keys to
        move, Home/End to jump, automatic activation. Keydown sits on the tabs
        rather than the tablist, because with a roving tabindex focus is always
        on a tab.
    </p>
    <Tabs
        label="Target configuration"
        bind:value={tab}
        tabs={[
            { value: 'overview', label: 'Overview' },
            { value: 'access', label: 'Access', badge: 3 },
            { value: 'keys', label: 'Host keys' },
            { value: 'archived', label: 'Archived', disabled: true },
        ]}
    >
        {#snippet children(active)}
            <p class="panel">Panel content for <code>{active}</code>.</p>
        {/snippet}
    </Tabs>
</section>

<!-- ══ Table ═══════════════════════════════════════════════════════ -->
<section>
    <h2>Table</h2>
    <p class="note">
        <strong>Wraps <code>common/ItemList.svelte</code></strong>
        — the search debounce, pagination, adjacency grouping and
        search-force-expand rule all stay there. Table adds only the sticky
        header, sortable headers, density toggle, keyboard navigation and row
        selection. Sorting is <em>surfaced, not applied</em>: ItemList owns row
        order because grouping is adjacency-based, so the caller feeds
        <code>sort</code>
        into its own <code>load</code>.
    </p>
    <p class="note">
        <strong>Keyboard:</strong>
        Tab into the table once, then ↑ ↓ to move, Home/End to jump, Space to
        select, Enter to activate. The tab stop is tracked by row key, so it
        survives a filter or a page change.
    </p>
    <Table
        caption="Demo sessions"
        {columns}
        load={loadDemo}
        rowKey={r => r.id}
        bind:density
        bind:selected={selectedRows}
        selectable
        showSearch
        onrowactivate={r => toast.info(`Activated ${r.target}`)}
    >
        {#snippet row(r)}
            <td><StatusMarker kind={r.status} bare /></td>
            <td>{r.user}</td>
            <td class="mono">{r.target}</td>
            <td>{r.proto}</td>
        {/snippet}
    </Table>

    <p class="label">Loading placeholder</p>
    <SkeletonRow rows={3} columns={[2, 3, 2, 1]} />

    <p class="label">Empty state</p>
    <EmptyState
        size="compact"
        title="No sessions yet"
        hint="Connections appear here as soon as a user opens one."
    >
        {#snippet action()}
            <Button variant="primary" size="compact">Add a target</Button>
        {/snippet}
    </EmptyState>
</section>

<!-- ══ Overlays ════════════════════════════════════════════════════ -->
<section>
    <h2>
        Modal, Drawer <span class="new">net-new</span>, Toast
        <span class="new">net-new</span>
    </h2>
    <p class="note">
        Modal and Drawer share one focus-trap action: focus moves in on open,
        Tab is held inside, the rest of the page goes <code>inert</code>, and
        focus returns to the trigger on close. Open one and press Tab — it will
        not escape — then Escape to close and confirm focus comes back here.
    </p>
    <div class="row">
        <Button onclick={() => (modalOpen = true)}>Open modal</Button>
        <Button onclick={() => (drawerOpen = true)}>Open drawer</Button>
    </div>

    <p class="label">
        Toasts — errors are sticky, everything else auto-dismisses; identical
        messages collapse with a count instead of stacking
    </p>
    <div class="row">
        <Button
            size="compact"
            onclick={() => toast.info('Configuration reloaded')}
        >
            Info
        </Button>
        <Button size="compact" onclick={() => toast.success('Target saved')}>
            Success
        </Button>
        <Button
            size="compact"
            onclick={() => toast.warning('Ticket expires in 10 minutes')}
        >
            Warning
        </Button>
        <Button
            size="compact"
            variant="destructive"
            onclick={() =>
                toast.error('Could not close session', {
                    detail: 'prod-bastion-01 did not respond within 5s',
                    action: { label: 'Retry', run: () => toast.success('Closed') },
                })}
        >
            Error (sticky)
        </Button>
    </div>
</section>

<!-- ══ Tooltip ═════════════════════════════════════════════════════ -->
<section>
    <h2>Tooltip</h2>
    <p class="note">
        Supplementary by definition: it <em>describes</em>, it never names. A
        control with no visible text needs a label, not a tooltip. Shows on
        hover and on keyboard focus, dismissable with Escape.
    </p>
    <div class="row">
        <Tooltip text="Closes every session on this target">
            <Button size="compact" variant="destructive">Close all</Button>
        </Tooltip>
        <Tooltip text="Below" placement="bottom">
            <Button size="compact">Bottom</Button>
        </Tooltip>
        <Tooltip text="To the right" placement="right">
            <Button size="compact">Right</Button>
        </Tooltip>
    </div>
</section>

<!-- ══ Audit ═══════════════════════════════════════════════════════ -->
<section>
    <h2>Primitive contrast audit</h2>
    <p class="note">
        Measured from what the browser actually painted for the components
        above, not from the token values. A token can be correct while a
        component that composes it is not.
    </p>
    <AuditTable caption="Rendered primitives" targets={AUDITS} />
</section>

<Modal bind:open={modalOpen} title="Close 3 sessions?" size="sm">
    <p>
        This disconnects the selected users immediately. Recordings already
        written are kept.
    </p>
    {#snippet footer()}
        <Button onclick={() => (modalOpen = false)}>Cancel</Button>
        <Button
            variant="destructive"
            click={async () => {
            await slowOk()
            modalOpen = false
        }}
        >
            Close sessions
        </Button>
    {/snippet}
</Modal>

<Drawer
    bind:open={drawerOpen}
    title="prod-bastion-01"
    subtitle="ssh · 10.12.4.8:22 · 4 roles"
>
    <div class="col">
        <Input label="Name" value="prod-bastion-01" />
        <Input label="Host" mono value="10.12.4.8" />
        <Toggle label="Enabled" checked />
        <TokenInput label="Allowed ranges" tokens={['10.0.0.0/8']} />
    </div>
    {#snippet footer()}
        <Button onclick={() => (drawerOpen = false)}>Cancel</Button>
        <Button variant="primary" click={slowOk}>Save</Button>
    {/snippet}
</Drawer>

<style>
    section {
        margin-bottom: var(--wg-space-3xl);
    }

    h2 {
        font: var(--wg-text-headline-md);
        margin: 0 0 var(--wg-space-sm);
    }

    .new {
        display: inline-block;
        vertical-align: middle;
        margin-left: var(--wg-space-xs);
        padding: 0 var(--wg-badge-padding-x);
        border: var(--wg-border-width) solid var(--wg-tertiary);
        border-radius: var(--wg-radius-badge);
        color: var(--wg-tertiary);
        font: var(--wg-text-label-sm);
    }

    .note {
        color: var(--wg-text-muted);
        font: var(--wg-text-body-md);
        margin: 0 0 var(--wg-space-md);
        max-width: 72ch;
    }

    .label {
        margin: var(--wg-space-lg) 0 var(--wg-space-sm);
        font: var(--wg-text-label-md);
        color: var(--wg-text-subtle);
    }

    .row {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: var(--wg-space-md);
    }

    .col {
        display: flex;
        flex-direction: column;
        gap: var(--wg-space-md);
        max-width: 28rem;
    }

    .grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr));
        gap: var(--wg-space-lg);
    }

    .panel {
        margin: 0;
        color: var(--wg-text-muted);
    }

    code {
        font: var(--wg-text-code-sm);
        color: var(--wg-text);
    }

    :global(.mono) {
        font-family: var(--wg-font-mono);
    }
</style>
