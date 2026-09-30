Fork of `ironrdp-dvc` 0.8.0.

## `DrdynvcClient::get_dvc_mut`

Backport of upstream IronRDP's by-type mutable DVC accessor (#1461): 0.8.0 can only
downcast a channel processor immutably, and the Graphics Pipeline compositor drain in
`vendor/ironrdp-session` has to take output out of `GraphicsPipelineClient`. The method is
upstream's verbatim; the private `DynamicChannelSet::get_by_type_id_mut` it relies on
mirrors the existing `get_by_type_id`.

Drop this fork once Warpgate builds against an `ironrdp-dvc` release that has
`get_dvc_mut` (anything after 0.8.0 cut from IronRDP master past #1461).

`Cargo.toml` is the published one; the source change is in `warpgate.patch`.
