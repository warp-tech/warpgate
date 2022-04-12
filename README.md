# Warpgate

<a href="https://github.com/warp-tech/warpgate/releases/latest"><img alt="GitHub All Releases" src="https://img.shields.io/github/downloads/warp-tech/warpgate/total.svg?label=DOWNLOADS&logo=github&style=for-the-badge"></a> &nbsp; <a href="https://nightly.link/warp-tech/warpgate/workflows/build/main"><img src="https://shields.io/badge/-Nightly%20Builds-orange?logo=hackthebox&logoColor=fff&style=for-the-badge"/></a> &nbsp;

Warpgate is a smart SSH bastion host for Linux that can be used with _any_ SSH client.

* Set it up in your DMZ, add user accounts and easily assign them to specific hosts within the network.
* Warpgate will record every session for you to replay and review later through a built-in admin web UI.
* Not a jump host - forwards your connections straight to the target instead.
* Single-file statically linked binary with no dependencies.
* Written in 100% safe Rust.

<img width="783" alt="image" src="https://user-images.githubusercontent.com/161476/162640762-a91a2816-48c0-44d9-8b03-5b1e2cb42d51.png">

## Getting started & downloads

* See the [Getting started](https://github.com/warp-tech/warpgate/wiki/Getting-started) wiki page.
* [Release / beta binaries](https://github.com/warp-tech/warpgate/releases)
* [Nightly builds](https://nightly.link/warp-tech/warpgate/workflows/build/main)

## Project Status

The project is currently in **alpha** stage and is gathering community feedback. See the [official roadmap](https://github.com/users/warp-tech/projects/1/views/2) for the upcoming features.

In particular, we're working on:

* Support for exposing HTTP(S) endpoints through the bastion,
* Support for tunneling database connections,
* Live session view and control,
* Requesting admin approval for sessions
* and much more.

## Contributing / building from source

* You'll need nightly Rust (will be installed automatically), NodeJS and Yarn
* Clone the repo
* [Just](https://github.com/casey/just) is used to run tasks - install it: `cargo install just`
* Install the admin UI deps: `just yarn`
* Build the API SDK: `just openapi-client`
* Build the frontend: `just yarn build`
* Build Warpgate: `cargo build` (optionally `--release`)

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/Eugeny"><img src="https://avatars.githubusercontent.com/u/161476?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Eugeny</b></sub></a><br /><a href="https://github.com/Eugeny/warpgate/commits?author=Eugeny" title="Code">💻</a></td>
    <td align="center"><a href="https://the-empire.systems/"><img src="https://avatars.githubusercontent.com/u/18178614?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Spencer Heywood</b></sub></a><br /><a href="https://github.com/Eugeny/warpgate/commits?author=heywoodlh" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/apiening"><img src="https://avatars.githubusercontent.com/u/2064875?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Andreas Piening</b></sub></a><br /><a href="https://github.com/Eugeny/warpgate/commits?author=apiening" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
