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
    cd warpgate-web && yarn {{ARGS}}

migrate *ARGS:
    cargo run -p warpgate-db-migrations -- {{ARGS}}

lint:
    cd warpgate-web && yarn run lint

svelte-check:
    cd warpgate-web && yarn run check

openapi-all:
    cd warpgate-web && yarn openapi-schema && yarn openapi-client

openapi:
    cd warpgate-web && yarn openapi-client

cleanup: (fix "--allow-dirty") (clippy "--fix" "--allow-dirty") fmt svelte-check lint
