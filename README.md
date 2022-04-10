# Warpgate

Warpgate is a smart SSH bastion host for Linux that can be used with _any_ SSH client.

* Set it up in your DMZ, add user accounts and easily assign them to specific hosts within the network.
* Warpgate will record every session for you to replay and review later through a built-in admin web UI.
* Not a jump host - forwards your connections straight to the target instead.
* Single-file statically linked binary with no dependencies.
* Written in 100% safe Rust.

<img width="783" alt="image" src="https://user-images.githubusercontent.com/161476/162640762-a91a2816-48c0-44d9-8b03-5b1e2cb42d51.png">

## Getting started

See the [Getting started](https://github.com/Eugeny/warpgate/wiki/Getting-started) wiki page.

## Project Status

The project is currently in **alpha** stage and is gathering community feedback. See the [official roadmap](https://github.com/users/Eugeny/projects/1/views/2) for the upcoming features.

In particular, we're working on:

* Support for exposing HTTP(S) endpoints through the bastion,
* Support for tunneling database connections,
* Live session view and control,
* Requesting admin approval for sessions
* and much more.

## Contributing / building from source

* Clone the repo
* [Just](https://github.com/casey/just) is used to run tasks - install it: `cargo install just`
* Install the admin UI deps: `just yarn`
* Build the API SDK: `just openapi-client`
* Build the frontend: `just yarn build`
* Build Warpgate: `cargo build` (optionally `--release`)
