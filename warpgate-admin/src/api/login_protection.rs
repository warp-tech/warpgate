use std::net::IpAddr;

use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use warpgate_common::WarpgateError;
use warpgate_core::Services;

use super::AnySecurityScheme;

pub struct Api;

#[derive(Object)]
struct BlockedIpInfo {
    ip_address: String,
    blocked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    block_count: i32,
    reason: String,
}

#[derive(Object)]
struct LockedUserInfo {
    username: String,
    locked_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    reason: String,
}

#[derive(Object)]
struct SecurityStatus {
    blocked_ip_count: u64,
    locked_user_count: u64,
    failed_attempts_last_hour: u64,
    failed_attempts_last_24h: u64,
}

#[derive(ApiResponse)]
enum ListBlockedIpsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<BlockedIpInfo>>),
}

#[derive(ApiResponse)]
enum UnblockIpResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 400)]
    InvalidIp,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum ListLockedUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<LockedUserInfo>>),
}

#[derive(ApiResponse)]
enum UnlockUserResponse {
    #[oai(status = 200)]
    Ok,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum SecurityStatusResponse {
    #[oai(status = 200)]
    Ok(Json<SecurityStatus>),
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/login-protection/blocked-ips",
        method = "get",
        operation_id = "list_blocked_ips"
    )]
    async fn list_blocked_ips(
        &self,
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<ListBlockedIpsResponse, WarpgateError> {
        let blocked_ips = services.login_protection.list_blocked_ips().await?;
        let result: Vec<BlockedIpInfo> = blocked_ips
            .into_iter()
            .map(|info| BlockedIpInfo {
                ip_address: info.ip_address.to_string(),
                blocked_at: info.blocked_at,
                expires_at: info.expires_at,
                block_count: info.block_count,
                reason: info.reason,
            })
            .collect();
        Ok(ListBlockedIpsResponse::Ok(Json(result)))
    }

    #[oai(
        path = "/login-protection/blocked-ips/:ip",
        method = "delete",
        operation_id = "unblock_ip"
    )]
    async fn unblock_ip(
        &self,
        services: Data<&Services>,
        ip: Path<String>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UnblockIpResponse, WarpgateError> {
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return Ok(UnblockIpResponse::InvalidIp),
        };

        services.login_protection.unblock_ip(&ip_addr).await?;
        Ok(UnblockIpResponse::Ok)
    }

    #[oai(
        path = "/login-protection/locked-users",
        method = "get",
        operation_id = "list_locked_users"
    )]
    async fn list_locked_users(
        &self,
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<ListLockedUsersResponse, WarpgateError> {
        let locked_users = services.login_protection.list_locked_users().await?;
        let result: Vec<LockedUserInfo> = locked_users
            .into_iter()
            .map(|info| LockedUserInfo {
                username: info.username,
                locked_at: info.locked_at,
                expires_at: info.expires_at,
                reason: info.reason,
            })
            .collect();
        Ok(ListLockedUsersResponse::Ok(Json(result)))
    }

    #[oai(
        path = "/login-protection/locked-users/:username",
        method = "delete",
        operation_id = "unlock_user"
    )]
    async fn unlock_user(
        &self,
        services: Data<&Services>,
        username: Path<String>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UnlockUserResponse, WarpgateError> {
        services
            .login_protection
            .unlock_user(&username.0)
            .await?;
        Ok(UnlockUserResponse::Ok)
    }

    #[oai(
        path = "/login-protection/status",
        method = "get",
        operation_id = "get_security_status"
    )]
    async fn get_security_status(
        &self,
        services: Data<&Services>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<SecurityStatusResponse, WarpgateError> {
        let status = services.login_protection.get_security_status().await?;
        Ok(SecurityStatusResponse::Ok(Json(SecurityStatus {
            blocked_ip_count: status.blocked_ip_count,
            locked_user_count: status.locked_user_count,
            failed_attempts_last_hour: status.failed_attempts_last_hour,
            failed_attempts_last_24h: status.failed_attempts_last_24h,
        })))
    }
}
