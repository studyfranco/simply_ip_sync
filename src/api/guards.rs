//! Every authorization decision, per `RBAC_MODEL.md`. Each function answers one question from
//! the specification and returns `Ok(())` or a refusal. Must not hold handler logic, response
//! types, or database writes.

use uuid::Uuid;

use crate::entities::{api_key, api_key_sync_permission};
use crate::error::AppError;

fn forbidden(msg: &str) -> AppError {
    AppError::Forbidden(msg.to_owned())
}

/// §1/R4: resource-creation rights (`can_manage_sources`, `can_manage_vaults`) are Master-grant-
/// only global flags, checked directly against the caller — never implied by `can_manage_keys`.
pub fn guard_resource_creation(caller: &api_key::Model, has_right: bool) -> Result<(), AppError> {
    if caller.is_master || has_right {
        Ok(())
    } else {
        Err(forbidden("missing the resource-creation right for this action"))
    }
}

/// R4: only the Master key may grant `can_manage_keys`, `can_manage_sources`, or
/// `can_manage_vaults` to any key (including itself, though granting is moot there). A parent key
/// can never mint another parent key or a resource-creation right.
pub fn guard_scope_elevation(
    caller: &api_key::Model,
    wants_can_manage_keys: bool,
    wants_can_manage_sources: bool,
    wants_can_manage_vaults: bool,
) -> Result<(), AppError> {
    if (wants_can_manage_keys || wants_can_manage_sources || wants_can_manage_vaults) && !caller.is_master {
        return Err(forbidden(
            "only the Master key may grant can_manage_keys, can_manage_sources, or can_manage_vaults",
        ));
    }
    Ok(())
}

/// R2: managing a specific resource (editing its configuration, or delegating permissions on it)
/// requires holding both global `can_manage_keys` AND a `can_manage = true` row for that specific
/// resource. Neither alone is sufficient, and `can_manage_keys` is never a bypass of per-resource
/// RBAC. Master bypasses everywhere.
pub fn guard_resource_manage(
    caller: &api_key::Model,
    permission: Option<&api_key_sync_permission::Model>,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }
    if caller.can_manage_keys && permission.is_some_and(|p| p.can_manage) {
        Ok(())
    } else {
        Err(forbidden(
            "managing this resource requires can_manage_keys and a can_manage grant on it (RBAC R2)",
        ))
    }
}

/// §3: resource lifecycle actions (delete, rename) are restricted to Master and the resource's
/// designated `owner_key_id`. Holding manage rights or any operational verb confers no lifecycle
/// authority.
pub fn guard_resource_lifecycle(caller: &api_key::Model, owner_key_id: Option<Uuid>) -> Result<(), AppError> {
    if caller.is_master || owner_key_id == Some(caller.id) {
        Ok(())
    } else {
        Err(forbidden("only the Master key or this resource's owner may delete or rename it (RBAC §3)"))
    }
}

/// Gate for `POST /api/sources/{id}/trigger` and `POST /api/sync-tasks/{id}/trigger`: the
/// caller's operational verb for this service (`can_sync`). Master bypasses; absence of a
/// permission row is a default-deny, not an implicit grant.
pub fn guard_can_sync(caller: &api_key::Model, permission: Option<&api_key_sync_permission::Model>) -> Result<(), AppError> {
    if caller.is_master || permission.is_some_and(|p| p.can_sync) {
        Ok(())
    } else {
        Err(forbidden("missing can_sync permission on this resource"))
    }
}

/// Visibility gate for a resource's `sync_logs`. Default-deny: no permission row means no
/// visibility, except for Master.
pub fn guard_can_view_logs(caller: &api_key::Model, permission: Option<&api_key_sync_permission::Model>) -> bool {
    caller.is_master || permission.is_some_and(|p| p.can_view_logs)
}

/// R1 (non-amplification) + R7 (granting bounded by R1 and R2 together): a caller may only grant
/// a verb it currently holds itself on the same resource, and granting anything at all first
/// requires R2's manage conjunction. Master bypasses (the only tier permitted to amplify, since it
/// is the root of all rights).
pub fn guard_delegated_grant(
    caller: &api_key::Model,
    caller_permission: Option<&api_key_sync_permission::Model>,
    grant_can_sync: bool,
    grant_can_manage: bool,
    grant_can_view_logs: bool,
) -> Result<(), AppError> {
    if caller.is_master {
        return Ok(());
    }
    guard_resource_manage(caller, caller_permission)?;
    let caller_has = |get: fn(&api_key_sync_permission::Model) -> bool| caller_permission.is_some_and(get);
    if grant_can_sync && !caller_has(|p| p.can_sync) {
        return Err(forbidden("cannot grant can_sync without holding it yourself on this resource (RBAC R1)"));
    }
    if grant_can_view_logs && !caller_has(|p| p.can_view_logs) {
        return Err(forbidden("cannot grant can_view_logs without holding it yourself on this resource (RBAC R1)"));
    }
    if grant_can_manage && !caller_has(|p| p.can_manage) {
        return Err(forbidden("cannot grant can_manage without holding it yourself on this resource (RBAC R1)"));
    }
    Ok(())
}

/// R6: revocation is never escalation. Reducing or removing a permission requires only manage
/// rights on the resource (R2) — the revoker need not hold the verb being removed, and may revoke
/// its own permissions.
pub fn guard_revocation(
    caller: &api_key::Model,
    caller_permission: Option<&api_key_sync_permission::Model>,
) -> Result<(), AppError> {
    guard_resource_manage(caller, caller_permission)
}

/// §5: the Master key is immutable through the API except for its own `bound_ips`. Called with
/// `changing_non_bound_ips_field = true` whenever an update payload touches anything besides
/// `bound_ips`.
pub fn guard_master_immutable(target_is_master: bool, changing_non_bound_ips_field: bool) -> Result<(), AppError> {
    if target_is_master && changing_non_bound_ips_field {
        Err(forbidden("the Master key is immutable through the API except for its own bound_ips (RBAC §5)"))
    } else {
        Ok(())
    }
}

/// §5: rotation is refused for every caller including the Master itself, since rotation returns a
/// fresh plaintext credential.
pub fn guard_rotation_allowed(target_is_master: bool) -> Result<(), AppError> {
    if target_is_master {
        Err(forbidden("the Master key's credentials cannot be rotated through the API (RBAC §5)"))
    } else {
        Ok(())
    }
}

/// Key management tier gate (Parent tier): creating/updating/deleting *other* API keys, or
/// managing their resource permission grants, requires `can_manage_keys`. Master bypasses.
pub fn guard_manage_keys(caller: &api_key::Model) -> Result<(), AppError> {
    if caller.is_master || caller.can_manage_keys {
        Ok(())
    } else {
        Err(forbidden("missing can_manage_keys"))
    }
}
