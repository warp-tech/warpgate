projects := "warpgate warpgate-admin warpgate-common warpgate-db-entities warpgate-db-migrations warpgate-protocol-ssh"

run *ARGS:
    RUST_BACKTRACE=1 RUST_LOG=warpgate cd warpgate && cargo run -- --config ../config.yaml {{ARGS}}

fmt:
    for p in {{projects}}; do cargo fmt -p $p -v; done

fix *ARGS:
    for p in {{projects}}; do cargo fix -p $p {{ARGS}}; done

clippy *ARGS:
    for p in {{projects}}; do cargo clippy -p $p {{ARGS}}; done

yarn *ARGS:
    cd warpgate-admin/app/ && yarn {{ARGS}}

migrate *ARGS:
    cargo run -p warpgate-db-migrations -- {{ARGS}}

svelte-check:
    cd warpgate-admin/app/ && yarn run check

openapi-all:
    cd warpgate-admin/app/ && yarn openapi-schema && yarn openapi-client

openapi:
    cd warpgate-admin/app/ && yarn openapi-client

cleanup: (fix "--allow-dirty") (clippy "--fix" "--allow-dirty") fmt
