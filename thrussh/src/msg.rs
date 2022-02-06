// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// https://tools.ietf.org/html/rfc4253#section-12
pub const DISCONNECT: u8 = 1;
#[allow(dead_code)]
pub const IGNORE: u8 = 2;
#[allow(dead_code)]
pub const UNIMPLEMENTED: u8 = 3;
#[allow(dead_code)]
pub const DEBUG: u8 = 4;

pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const KEXINIT: u8 = 20;
pub const NEWKEYS: u8 = 21;

// http://tools.ietf.org/html/rfc5656#section-7.1
pub const KEX_ECDH_INIT: u8 = 30;
pub const KEX_ECDH_REPLY: u8 = 31;

// https://tools.ietf.org/html/rfc4250#section-4.1.2
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const USERAUTH_BANNER: u8 = 53;
pub const USERAUTH_PK_OK: u8 = 60;

// https://tools.ietf.org/html/rfc4256#section-5
pub const USERAUTH_INFO_REQUEST: u8 = 60;
pub const USERAUTH_INFO_RESPONSE: u8 = 61;

// https://tools.ietf.org/html/rfc4254#section-9
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_SUCCESS: u8 = 81;
pub const REQUEST_FAILURE: u8 = 82;

pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;
