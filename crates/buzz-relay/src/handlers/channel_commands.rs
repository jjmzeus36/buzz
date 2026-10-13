//! Accepted channel commands persist canonical state and mandatory notices together.

use super::channel_authz::{self, PutUserDecision, RemoveOtherDecision};
use crate::state::AppState;
use buzz_core::{
    kind::{KIND_MEMBER_ADDED_NOTIFICATION, KIND_MEMBER_REMOVED_NOTIFICATION},
    TenantContext,
};
use buzz_db::channel::{ChannelUpdate, MemberRole};
use buzz_db::channel_command::{ChannelCommandCommit, ChannelCommandMutation, ChannelMetadataEdit};
use nostr::{Event, EventBuilder, Kind, Tag};
use std::sync::Arc;
use uuid::Uuid;

fn value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event
        .tags
        .iter()
        .find(|t| t.kind().to_string() == name)
        .and_then(|t| t.content())
}
fn denied(error: impl std::fmt::Display) -> buzz_db::DbError {
    buzz_db::DbError::AccessDenied(error.to_string())
}
fn invalid(error: impl std::fmt::Display) -> buzz_db::DbError {
    buzz_db::DbError::InvalidData(error.to_string())
}
fn notice(
    state: &AppState,
    source: &Event,
    channel: Uuid,
    kind: u32,
    content: serde_json::Value,
    target: Option<&str>,
    ordinal: usize,
) -> anyhow::Result<Event> {
    // Bind identity to the source and signed-order occurrence. Relay acceptance
    // time preserves live subscription and client ordering with skewed senders.
    // Successful exact retries never regenerate notices.
    let mut tags = vec![
        Tag::parse(["h", &channel.to_string()])?,
        Tag::parse(["e", &source.id.to_hex()])?,
        Tag::parse(["command_notice", &ordinal.to_string()])?,
    ];
    if let Some(target) = target {
        tags.push(Tag::parse(["p", target])?);
    }
    Ok(
        EventBuilder::new(Kind::Custom(kind as u16), content.to_string())
            .tags(tags)
            .allow_self_tagging()
            .sign_with_keys(&state.relay_keypair)?,
    )
}

/// Recheck current authority on the held writer snapshot and atomically persist
/// source, every canonical edit, and direct/system notifications.
pub async fn persist(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    event: &Event,
    channel: Uuid,
    trusted_owner: Option<&nostr::PublicKey>,
    thread_meta: Option<buzz_db::event::ThreadMetadataParams<'_>>,
) -> anyhow::Result<ChannelCommandCommit> {
    if event.kind.as_u16() == 9002 {
        super::side_effects::validate_metadata_tags(event).map_err(invalid)?;
    }
    let mut guard = state
        .db
        .lock_channel_command(
            tenant.community(),
            channel,
            event,
            trusted_owner.map(|key| key.as_bytes().as_slice()),
        )
        .await?;
    if let Some(source) = guard.existing_receipt().await? {
        guard.rollback().await?;
        return Ok(ChannelCommandCommit {
            source,
            inserted: false,
            notices: Vec::new(),
        });
    }
    let kind = event.kind.as_u16();
    let actor = event.pubkey.to_bytes();
    let actor_hex = event.pubkey.to_hex();
    let actor_role: Option<MemberRole> = guard
        .members
        .iter()
        .find(|m| m.pubkey == actor)
        .and_then(|m| m.role.parse().ok());
    let unarchive = kind == 9002
        && event
            .tags
            .iter()
            .any(|t| t.kind().to_string() == "archived" && t.content() == Some("false"));
    if guard.channel.archived_at.is_some() && !unarchive {
        return Err(denied("channel is archived").into());
    }
    let mut notices = Vec::new();
    let mutation = match kind {
        9000 | 9001 => {
            let target = buzz_db::channel_command::command_member_target(event)
                .ok_or_else(|| invalid("missing p tag"))?;
            let target_hex = hex::encode(&target);
            let mutation = if kind == 9000 {
                let requested = value(event, "role")
                    .map(str::parse::<MemberRole>)
                    .transpose()
                    .map_err(invalid)?;
                let decision = channel_authz::decide_put_user(
                    &guard.channel.visibility,
                    actor_role,
                    requested,
                    &guard.members,
                    &target,
                    &actor,
                )
                .map_err(denied)?;
                if matches!(decision, PutUserDecision::CheckAddPolicy) {
                    if let Some((policy, owner)) = &guard.target_policy {
                        channel_authz::decide_channel_add_policy(policy, owner.as_deref(), &actor)
                            .map_err(denied)?;
                    }
                }
                let role = requested
                    .or_else(|| {
                        guard
                            .members
                            .iter()
                            .find(|m| m.pubkey == target)
                            .and_then(|m| m.role.parse().ok())
                    })
                    .unwrap_or(MemberRole::Member);
                ChannelCommandMutation::PutMember(role)
            } else {
                if target == actor {
                    channel_authz::decide_self_departure(&guard.members, &actor).map_err(denied)?;
                } else {
                    match channel_authz::classify_remove_other(&guard.members, &actor) {
                        RemoveOtherDecision::Allow => {}
                        RemoveOtherDecision::CheckAgentOwner
                            if guard
                                .target_policy
                                .as_ref()
                                .and_then(|(_, owner)| owner.as_deref())
                                == Some(actor.as_slice()) => {}
                        _ => return Err(denied("actor not authorized").into()),
                    }
                }
                ChannelCommandMutation::RemoveMember
            };
            let message_type = if kind == 9000 {
                "member_joined"
            } else if target == actor {
                "member_left"
            } else {
                "member_removed"
            };
            notices.push((
                notice(
                    state,
                    event,
                    channel,
                    40099,
                    serde_json::json!({"type":message_type,"actor":actor_hex,"target":target_hex}),
                    None,
                    notices.len(),
                )?,
                Some(channel),
            ));
            let notification_kind = if kind == 9000 {
                KIND_MEMBER_ADDED_NOTIFICATION
            } else {
                KIND_MEMBER_REMOVED_NOTIFICATION
            };
            let notification_type = if kind == 9000 {
                "member_added"
            } else {
                "member_removed"
            };
            notices.push((notice(state, event, channel, notification_kind, serde_json::json!({"type":notification_type,"channel_id":channel.to_string(),"actor":actor_hex}), Some(&target_hex), notices.len())?, None));
            mutation
        }
        9002 => {
            let privileged = event.tags.iter().any(|t| {
                matches!(
                    t.kind().to_string().as_str(),
                    "name" | "about" | "archived" | "visibility" | "ttl"
                )
            });
            if privileged {
                if !actor_role.is_some_and(|r| r.is_elevated()) && !guard.owns_owner_agent {
                    return Err(denied(
                        "actor not authorized for name/about/archived/visibility/ttl changes",
                    )
                    .into());
                }
            } else if actor_role.is_none() {
                return Err(denied("not a member").into());
            }
            let mut edits = Vec::new();
            for tag in event.tags.iter() {
                let Some(val) = tag.content() else {
                    continue;
                };
                let mut payload = None;
                match tag.kind().to_string().as_str() {
                    "name" => edits.push(ChannelMetadataEdit::Update(ChannelUpdate {
                        name: Some(val.into()),
                        ..Default::default()
                    })),
                    "about" => edits.push(ChannelMetadataEdit::Update(ChannelUpdate {
                        description: Some(val.into()),
                        ..Default::default()
                    })),
                    "topic" => {
                        edits.push(ChannelMetadataEdit::Topic(val.into()));
                        payload = Some(
                            serde_json::json!({"type":"topic_changed","actor":actor_hex,"topic":val}),
                        );
                    }
                    "purpose" => {
                        edits.push(ChannelMetadataEdit::Purpose(val.into()));
                        payload = Some(
                            serde_json::json!({"type":"purpose_changed","actor":actor_hex,"purpose":val}),
                        );
                    }
                    "visibility" => {
                        if !matches!(val, "open" | "private") {
                            return Err(invalid("invalid visibility").into());
                        }
                        edits.push(ChannelMetadataEdit::Update(ChannelUpdate {
                            visibility: Some(val.into()),
                            ..Default::default()
                        }));
                        payload = Some(
                            serde_json::json!({"type":"visibility_changed","actor":actor_hex,"visibility":val}),
                        );
                    }
                    "ttl" => {
                        let ttl = if val.is_empty() {
                            None
                        } else {
                            let n = val.parse::<i32>().map_err(invalid)?;
                            if n <= 0 {
                                return Err(invalid("ttl must be positive").into());
                            }
                            Some(n)
                        };
                        edits.push(ChannelMetadataEdit::Update(ChannelUpdate {
                            ttl_seconds: Some(ttl),
                            ..Default::default()
                        }));
                        payload = Some(
                            serde_json::json!({"type":"ttl_changed","actor":actor_hex,"ttl_seconds":ttl}),
                        );
                    }
                    "archived" => {
                        let archived = match val {
                            "true" => true,
                            "false" => false,
                            _ => return Err(invalid("invalid archived value").into()),
                        };
                        edits.push(ChannelMetadataEdit::Archived(archived));
                        payload = Some(
                            serde_json::json!({"type":if archived {"channel_archived"} else {"channel_unarchived"},"actor":actor_hex}),
                        );
                    }
                    _ => {}
                }
                if let Some(payload) = payload {
                    notices.push((
                        notice(state, event, channel, 40099, payload, None, notices.len())?,
                        Some(channel),
                    ));
                }
            }
            ChannelCommandMutation::Metadata(edits)
        }
        _ => return Err(invalid("unsupported atomic channel command").into()),
    };
    Ok(guard.commit(mutation, notices, thread_meta).await?)
}

#[cfg(test)]
mod postgres_tests;
