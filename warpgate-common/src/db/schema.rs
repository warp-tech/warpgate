table! {
    sessions (id) {
        id -> Binary,
        target_snapshot -> Nullable<Text>,
        user_snapshot -> Nullable<Text>,
        remote_address -> Text,
        started -> Timestamp,
        ended -> Nullable<Timestamp>,
    }
}
