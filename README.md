<p align="center">
<img src="https://github.com/user-attachments/assets/89be835b-ff96-46df-94c7-ae2d176615e3" />
</p>

<br/>


<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/readme/brand-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="warpgate-web/public/assets/brand.svg">
  <img alt="Shows a black logo in light color mode and a white one in dark color mode." src=".github/readme/brand-dark.svg">
</picture>
</p>

<br/>
<p align="center">
<a href="https://github.com/warp-tech/warpgate/releases/latest"><img alt="GitHub All Releases" src="https://img.shields.io/github/downloads/warp-tech/warpgate/total.svg?label=DOWNLOADS&logo=github&style=for-the-badge&color=8f8"></a> &nbsp; <a href="https://nightly.link/warp-tech/warpgate/workflows/build/main"><img src="https://shields.io/badge/-Nightly%20Builds-fa5?logo=hackthebox&logoColor=444&style=for-the-badge"/></a> &nbsp; <a href="https://discord.gg/Vn7BjmzhtF"><img alt="Discord" src="https://img.shields.io/discord/1280890060195233934?style=for-the-badge&color=acc&logo=discord&logoColor=white&label=Discord"></a>
</p>


<p align="center">
  <a href="https://ko-fi.com/J3J8KWTF">
    <img src="https://cdn.ko-fi.com/cdn/kofi3.png?v=2" width="150">
  </a>
</p>

---

Warpgate is a smart & fully transparent SSH, HTTPS, MySQL and PostgreSQL bastion host that doesn't require a client app or an SSH wrapper.

* Set it up in your DMZ, add user accounts and easily assign them to specific hosts and URLs within the network.
* Warpgate will record every session for you to view (live) and replay later through a built-in admin web UI.
* Not a jump host - forwards connection straight to the target in a way that's fully transparent to the client.
* Native 2FA and SSO support (TOTP & OpenID Connect)
* Single binary with no dependencies.
* Written in 100% safe Rust.

## Getting started & downloads

* See the [Getting started](https://warpgate.null.page/getting-started/) docs page (or [Getting started on Docker](https://warpgate.null.page/getting-started-on-docker/)).
* [Release / beta binaries](https://github.com/warp-tech/warpgate/releases)
* [Nightly builds](https://nightly.link/warp-tech/warpgate/workflows/build/main)

## How is Warpgate different from a jump host / VPN / Teleport?

| Warpgate | SSH jump host | VPN | Teleport |
|-|-|-|-|
| ✅ **Precise 1:1 assignment between users and services** | (Usually) full access to the network behind the jump host | (Usually) full access to the network | ✅ **Precise 1:1 assignment between users and services** |
| ✅ **No custom client needed** | Jump host config needed | ✅ **No custom client needed** | Custom client required |
| ✅ **2FA out of the box** | 🟡 2FA possible with additional PAM plugins | 🟡 Depends on the provider | ✅ **2FA out of the box** |
| ✅ **SSO out of the box** | 🟡 SSO possible with additional PAM plugins | 🟡 Depends on the provider | Paid |
| ✅ **Command-level audit** | 🟡 Connection-level audit on the jump host, no secure audit on the target if root access is given | No secure audit on the target if root access is given | ✅ **Command-level audit** |
| ✅ **Full session recording** | No secure recording possible on the target if root access is given | No secure recording possible on the target if root access is given | ✅ **Full session recording** |
| ✅ **Non-interactive connections** | 🟡 Non-interactive connections are possible if the clients supports jump hosts natively | ✅ **Non-interactive connections** | Non-interactive connections require using an SSH client wrapper or running a tunnel |
| ✅ **Self-hosted, you own the data** | ✅ **Self-hosted, you own the data** | 🟡 Depends on the provider | SaaS |

<center>
      <img width="783" alt="image" src="https://user-images.githubusercontent.com/161476/162640762-a91a2816-48c0-44d9-8b03-5b1e2cb42d51.png">
</center>

<table>
  <tr>
  <td>
    <img src="https://github.com/user-attachments/assets/c9a6a372-198e-4f46-ab86-8c420dc24bca">
  </td>
  <td>
    <img src="https://github.com/user-attachments/assets/a2166426-e865-4aba-9600-520954bcfe7f">
  </td>
  <td>
    <img src="https://github.com/user-attachments/assets/366a5afb-aa86-4902-9080-eb2f40bf162c">
  </td>
  </tr>
</table>

## Reporting security issues

Please use GitHub's [vulnerability reporting system](https://github.com/warp-tech/warpgate/security/policy).

## Project Status

The project is ready for production.

## How it works

Warpgate is a service that you deploy on the bastion/DMZ host, which will accept SSH, HTTPS, MySQL and PostgreSQL connections and provide an (optional) web admin UI.

Run `warpgate setup` to interactively generate a config file, including port bindings. See [Getting started](https://warpgate.null.page/getting-started/) for details.

It receives connections with specifically formatted credentials, authenticates the user locally, connects to the target itself, and then connects both parties together while (optionally) recording the session.

When connecting through HTTPS, Warpgate presents a selection of available targets, and will then proxy all traffic in a session to the selected target. You can switch between targets at any time.

You manage the target and user lists and assign them to each other through the admin UI, and the session history is stored in an SQLite database (default: in `/var/lib/warpgate`).

You can also use the admin web interface to view the live session list, review session recordings, logs and more.

## Contributing / building from source

* You'll need Rust, NodeJS and NPM
* Clone the repo
* [Just](https://github.com/casey/just) is used to run tasks - install it: `cargo install just`
* Install the admin UI deps: `just npm install`
* Build the frontend: `just npm run build`
* Build Warpgate: `cargo build` (optionally `--release`)

The binary is in `target/{debug|release}`.

### Tech stack

* Rust 🦀
  * HTTP: `poem-web`
  * Database: SQLite via `sea-orm` + `sqlx`
  * SSH: `russh`
* Typescript
  * Svelte
  * Bootstrap

### Backend API

* Warpgate admin and user facing APIs use autogenerated OpenAPI schemas and SDKs. To update the SDKs after changing the query/response structures, run `just openapi-all`.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Eugeny"><img src="https://avatars.githubusercontent.com/u/161476?v=4?s=100" width="100px;" alt="Eugeny"/><br /><sub><b>Eugeny</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=Eugeny" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://the-empire.systems/"><img src="https://avatars.githubusercontent.com/u/18178614?v=4?s=100" width="100px;" alt="Spencer Heywood"/><br /><sub><b>Spencer Heywood</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=heywoodlh" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/apiening"><img src="https://avatars.githubusercontent.com/u/2064875?v=4?s=100" width="100px;" alt="Andreas Piening"/><br /><sub><b>Andreas Piening</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=apiening" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Gurkengewuerz"><img src="https://avatars.githubusercontent.com/u/10966337?v=4?s=100" width="100px;" alt="Niklas"/><br /><sub><b>Niklas</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=Gurkengewuerz" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/notnooblord"><img src="https://avatars.githubusercontent.com/u/11678665?v=4?s=100" width="100px;" alt="Nooblord"/><br /><sub><b>Nooblord</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=notnooblord" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://shea.nz/"><img src="https://avatars.githubusercontent.com/u/51303984?v=4?s=100" width="100px;" alt="Shea Smith"/><br /><sub><b>Shea Smith</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=SheaSmith" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/samtoxie"><img src="https://avatars.githubusercontent.com/u/7732658?v=4?s=100" width="100px;" alt="samtoxie"/><br /><sub><b>samtoxie</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=samtoxie" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://sixteenink.com"><img src="https://avatars.githubusercontent.com/u/1480236?v=4?s=100" width="100px;" alt="Skyler Lewis"/><br /><sub><b>Skyler Lewis</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=alairock" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://www.mohammednoureldin.com"><img src="https://avatars.githubusercontent.com/u/14913147?v=4?s=100" width="100px;" alt="Mohammed Noureldin"/><br /><sub><b>Mohammed Noureldin</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=MohammedNoureldin" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mrmm"><img src="https://avatars.githubusercontent.com/u/796467?v=4?s=100" width="100px;" alt="Mourad Maatoug"/><br /><sub><b>Mourad Maatoug</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=mrmm" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://justinforlenza.dev"><img src="https://avatars.githubusercontent.com/u/11709872?v=4?s=100" width="100px;" alt="Justin"/><br /><sub><b>Justin</b></sub></a><br /><a href="https://github.com/warp-tech/warpgate/commits?author=justinforlenza" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
