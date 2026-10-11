//! Validate profile metadata before its atomic event/projection write.

use buzz_core::TenantContext;
use buzz_db::profile_event::ProfileMetadata;
use nostr::Event;

pub(super) fn prepare(tenant: &TenantContext, event: &Event) -> Result<ProfileMetadata, String> {
    let content: serde_json::Value = serde_json::from_str(&event.content)
        .map_err(|_| "kind:0 content must be valid JSON".to_string())?;
    let text = |name: &str, fallback: &str| {
        content
            .get(name)
            .or_else(|| content.get(fallback))
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let profile = ProfileMetadata {
        display_name: text("display_name", "name"),
        avatar_url: text("picture", "image"),
        about: text("about", "about"),
        nip05_handle: content
            .get("nip05")
            .and_then(|value| value.as_str())
            .and_then(|raw| crate::api::nip05::canonicalize_nip05(raw, tenant.host()).ok()),
    };
    profile.validate().map_err(|error| error.to_string())?;
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind};

    #[test]
    fn profile_preparation_enforces_character_limit_and_bound_host() {
        let tenant = TenantContext::resolved(
            buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4()),
            "workspace.example",
        );
        let keys = Keys::generate();
        let make = |name: String, nip05: &str| {
            EventBuilder::new(
                Kind::Metadata,
                serde_json::json!({"display_name":name,"nip05":nip05}).to_string(),
            )
            .sign_with_keys(&keys)
            .expect("event")
        };
        let valid = prepare(&tenant, &make("é".repeat(255), "Alice@workspace.example"))
            .expect("valid Unicode profile");
        assert_eq!(
            valid.nip05_handle.as_deref(),
            Some("alice@workspace.example")
        );
        assert!(prepare(&tenant, &make("x".repeat(256), "")).is_err());
        assert_eq!(
            prepare(&tenant, &make("name".into(), "alice@other.example"))
                .expect("off-domain cleared")
                .nip05_handle,
            None
        );
    }
}

#[cfg(test)]
mod postgres_tests;
