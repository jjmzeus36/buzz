//! Transaction boundary for accepted NIP-29 commands and canonical channel state.

use buzz_core::{CommunityId, StoredEvent};
use nostr::Event;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::channel::{ChannelRecord, ChannelUpdate, MemberRecord, MemberRole};
use crate::{Db, DbError, Result};

/// A metadata edit in signed tag order.
pub enum ChannelMetadataEdit {
    /// Name, description, visibility, or TTL changes.
    Update(ChannelUpdate),
    /// Topic and its authenticated author attribution.
    Topic(String),
    /// Purpose and its authenticated author attribution.
    Purpose(String),
    /// Archive (`true`) or restore (`false`).
    Archived(bool),
}

/// Canonical mutation whose authority is checked against a locked snapshot.
pub enum ChannelCommandMutation {
    /// Add or update the source event's target member.
    PutMember(MemberRole),
    /// Remove the source event's target member.
    RemoveMember,
    /// Apply every recognized metadata tag atomically, in signed order.
    Metadata(Vec<ChannelMetadataEdit>),
}

/// Durable source and notices; callers may dispatch only after this commit.
pub struct ChannelCommandCommit {
    /// The exact signed source command.
    pub source: StoredEvent,
    /// False for an exact replay; no historical mutation or notice was reapplied.
    pub inserted: bool,
    /// Newly inserted relay-signed notices, ready for post-commit dispatch.
    pub notices: Vec<StoredEvent>,
}

/// Current source authority held through command and notice persistence.
pub struct LockedChannelCommand {
    /// Current canonical channel, protected against concurrent metadata changes.
    pub channel: ChannelRecord,
    /// Active members protected by membership and row locks.
    pub members: Vec<MemberRecord>,
    /// Target's current add policy and immutable agent owner.
    pub target_policy: Option<(String, Option<Vec<u8>>)>,
    /// Whether the actor owns any active owner-role agent in this channel.
    pub owns_owner_agent: bool,
    community: CommunityId,
    actor: Vec<u8>,
    target: Option<Vec<u8>>,
    source: Event,
    workflow_ids: Vec<Uuid>,
    tx: Transaction<'static, Postgres>,
}

/// Resolve the first valid 32-byte `p` tag, matching existing NIP-29 validation.
/// Malformed earlier tags do not shadow a later valid membership target.
pub fn command_member_target(event: &Event) -> Option<Vec<u8>> {
    event.tags.iter().find_map(|tag| {
        if tag.kind().to_string() != "p" {
            return None;
        }
        hex::decode(tag.content()?)
            .ok()
            .filter(|bytes| bytes.len() == 32)
    })
}

impl Db {
    /// Lock current command authority using lifecycle, TTL, membership, then
    /// workflow/channel/member row order. Workflow prelocks precede member rows
    /// to agree with approval recovery's workflow-then-member lock order.
    /// `trusted_owner` must come from cryptographically verified authentication.
    pub async fn lock_channel_command(
        &self,
        community: CommunityId,
        channel_id: Uuid,
        source: &Event,
        trusted_owner: Option<&[u8]>,
    ) -> Result<LockedChannelCommand> {
        let kind = source.kind.as_u16();
        if !matches!(kind, 9000..=9002)
            || !source.tags.iter().any(|t| {
                t.as_slice().first().is_some_and(|v| v == "h")
                    && t.content().and_then(|v| Uuid::parse_str(v).ok()) == Some(channel_id)
            })
        {
            return Err(DbError::InvalidData(
                "command/channel binding mismatch".into(),
            ));
        }
        let actor = source.pubkey.to_bytes().to_vec();
        let target = if matches!(kind, 9000 | 9001) {
            Some(
                command_member_target(source)
                    .ok_or_else(|| DbError::InvalidData("missing member target".into()))?,
            )
        } else {
            None
        };
        let mut tx = self.begin_event_write_transaction().await?;
        sqlx::query("SELECT assert_community_write_allowed($1)")
            .bind(community.as_uuid())
            .execute(&mut *tx)
            .await?;
        let active: Option<bool> = sqlx::query_scalar("SELECT TRUE FROM communities WHERE id = $1 AND archived_at IS NULL AND deleted_at IS NULL AND deletion_state = 'active' FOR SHARE")
            .bind(community.as_uuid()).fetch_optional(&mut *tx).await?;
        if active != Some(true) {
            return Err(DbError::AccessDenied(
                "command requires an active community".into(),
            ));
        }
        // Metadata can change TTL while source and notices also run its event
        // trigger. Take exclusive up front; never upgrade after channel locks.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "buzz_channel_ttl:{}:{}",
                community.as_uuid(),
                channel_id
            ))
            .execute(&mut *tx)
            .await?;
        crate::channel_members::acquire_channel_membership_lock(&mut tx, community, channel_id)
            .await?;
        let workflow_ids = if kind == 9001 {
            sqlx::query_scalar("SELECT id FROM workflows WHERE community_id = $1 AND channel_id = $2 AND owner_pubkey = $3 AND enabled = TRUE ORDER BY id FOR UPDATE")
                .bind(community.as_uuid()).bind(channel_id).bind(target.as_deref()).fetch_all(&mut *tx).await?
        } else {
            Vec::new()
        };
        let row = sqlx::query(
            "SELECT id, name, channel_type::text AS channel_type, visibility::text AS visibility, description, canvas, created_by, created_at, updated_at, archived_at, deleted_at, nip29_group_id, topic_required, max_members, topic, topic_set_by, topic_set_at, purpose, purpose_set_by, purpose_set_at, ttl_seconds, ttl_deadline FROM channels WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE")
            .bind(community.as_uuid()).bind(channel_id).fetch_optional(&mut *tx).await?
            .ok_or(DbError::ChannelNotFound(channel_id))?;
        let channel = crate::channel::row_to_channel_record(row)?;
        let members =
            crate::channel_members::get_members_tx(&mut tx, community, channel_id).await?;
        // Rows can be absent for channel members. Materialize actor and target
        // in a common order so cross-channel A->B / B->A commands cannot each
        // hold one uncommitted user insert while waiting on the other.
        let mut principals = vec![actor.clone()];
        principals.extend(target.iter().cloned());
        principals.sort();
        principals.dedup();
        for principal in principals {
            sqlx::query(
                "INSERT INTO users (community_id, pubkey) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(community.as_uuid())
            .bind(principal)
            .execute(&mut *tx)
            .await?;
        }
        super::channel_topic_authority::lock_unrestricted_principal_with_owner(
            &mut tx,
            community,
            &actor,
            trusted_owner,
        )
        .await?;
        // Lock canonical policy through commit, including a newly materialized
        // default, so an absent row cannot hide a concurrent restrictive update.
        let target_policy = if let Some(target) = &target {
            sqlx::query_as("SELECT channel_add_policy::text, agent_owner_pubkey FROM users WHERE community_id = $1 AND pubkey = $2 FOR SHARE")
                .bind(community.as_uuid()).bind(target).fetch_optional(&mut *tx).await?
        } else {
            None
        };
        let owner_keys: Vec<Vec<u8>> = members
            .iter()
            .filter(|m| m.role == "owner")
            .map(|m| m.pubkey.clone())
            .collect();
        let owned: Vec<Vec<u8>> = sqlx::query_scalar("SELECT pubkey FROM users WHERE community_id = $1 AND agent_owner_pubkey = $2 AND pubkey = ANY($3::bytea[]) ORDER BY pubkey FOR SHARE")
            .bind(community.as_uuid()).bind(&actor).bind(&owner_keys).fetch_all(&mut *tx).await?;
        Ok(LockedChannelCommand {
            channel,
            members,
            target_policy,
            owns_owner_agent: !owned.is_empty(),
            community,
            actor,
            target,
            source: source.clone(),
            workflow_ids,
            tx,
        })
    }
}

impl LockedChannelCommand {
    /// Recheck the exact receipt after serialization: concurrent requests may
    /// both miss the early lookup before one commits self-removal or archival.
    /// Callers classify this before mutable channel/member policy and roll back
    /// this guard, so even incidental principal sentinels leave no new rows.
    pub async fn existing_receipt(&mut self) -> Result<Option<StoredEvent>> {
        let row = sqlx::query("SELECT id, pubkey, created_at, kind, tags, content, sig, received_at, channel_id FROM events WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1")
            .bind(self.community.as_uuid()).bind(self.source.id.as_bytes().as_slice())
            .fetch_optional(&mut *self.tx).await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored = crate::event::row_to_stored_event(row)?
            .ok_or_else(|| DbError::InvalidData("invalid stored command receipt".into()))?;
        if stored.event != self.source || stored.channel_id != Some(self.channel.id) {
            return Err(DbError::InvalidData(
                "command receipt does not match signed source".into(),
            ));
        }
        Ok(Some(stored))
    }

    /// Release a classified receipt without persisting any incidental guard writes.
    pub async fn rollback(self) -> Result<()> {
        self.tx.rollback().await?;
        Ok(())
    }

    /// Persist source, authorized canonical mutation and mandatory notices in
    /// one transaction. Exact source replay commits no mutation or new notice.
    pub async fn commit(
        mut self,
        mutation: ChannelCommandMutation,
        notices: Vec<(Event, Option<Uuid>)>,
        thread_meta: Option<crate::event::ThreadMetadataParams<'_>>,
    ) -> Result<ChannelCommandCommit> {
        let source = crate::event::insert_event_with_thread_metadata_tx(
            &mut self.tx,
            self.community,
            &self.source,
            Some(self.channel.id),
            thread_meta,
        )
        .await?;
        if !source.1 {
            self.tx.commit().await?;
            return Ok(ChannelCommandCommit {
                source: source.0,
                inserted: false,
                notices: Vec::new(),
            });
        }
        crate::insert_mentions_in_transaction(
            &mut self.tx,
            self.community,
            &self.source,
            Some(self.channel.id),
        )
        .await?;
        match (self.source.kind.as_u16(), mutation) {
            (9000, ChannelCommandMutation::PutMember(role)) => {
                let target = self
                    .target
                    .as_deref()
                    .ok_or_else(|| DbError::InvalidData("missing target".into()))?;
                crate::channel_members::add_member_tx(
                    &mut self.tx,
                    self.community,
                    self.channel.id,
                    target,
                    role,
                    Some(&self.actor),
                )
                .await?;
            }
            (9001, ChannelCommandMutation::RemoveMember) => {
                let target = self
                    .target
                    .as_deref()
                    .ok_or_else(|| DbError::InvalidData("missing target".into()))?;
                crate::channel_members::remove_member_tx(
                    &mut self.tx,
                    self.community,
                    self.channel.id,
                    target,
                    &self.actor,
                )
                .await?;
                // Existing rows are locked before member rows. A separately
                // preauthorized new workflow INSERT remains a distinct writer
                // protocol limitation; the per-fire authority gate still denies.
                sqlx::query("UPDATE workflows SET enabled = FALSE WHERE community_id = $1 AND id = ANY($2::uuid[])")
                    .bind(self.community.as_uuid()).bind(&self.workflow_ids).execute(&mut *self.tx).await?;
            }
            (9002, ChannelCommandMutation::Metadata(edits)) => {
                for edit in edits {
                    match edit {
                        ChannelMetadataEdit::Update(update) => {
                            crate::channel::update_channel_tx(
                                &mut self.tx,
                                self.community,
                                self.channel.id,
                                update,
                            )
                            .await?
                        }
                        ChannelMetadataEdit::Topic(topic) => {
                            crate::channel::set_topic_tx(
                                &mut self.tx,
                                self.community,
                                self.channel.id,
                                &topic,
                                &self.actor,
                            )
                            .await?
                        }
                        ChannelMetadataEdit::Purpose(purpose) => {
                            crate::channel::set_purpose_tx(
                                &mut self.tx,
                                self.community,
                                self.channel.id,
                                &purpose,
                                &self.actor,
                            )
                            .await?
                        }
                        ChannelMetadataEdit::Archived(true) => {
                            crate::channel::archive_channel_tx(
                                &mut self.tx,
                                self.community,
                                self.channel.id,
                            )
                            .await?
                        }
                        ChannelMetadataEdit::Archived(false) => {
                            crate::channel::unarchive_channel_tx(
                                &mut self.tx,
                                self.community,
                                self.channel.id,
                            )
                            .await?
                        }
                    }
                }
            }
            _ => {
                return Err(DbError::InvalidData(
                    "command mutation kind mismatch".into(),
                ))
            }
        }
        let mut stored_notices = Vec::new();
        for (event, channel) in notices {
            let (stored, inserted) = crate::event::insert_event_in_transaction(
                &mut self.tx,
                self.community,
                &event,
                channel,
            )
            .await?;
            if inserted {
                crate::insert_mentions_in_transaction(
                    &mut self.tx,
                    self.community,
                    &event,
                    channel,
                )
                .await?;
                stored_notices.push(stored);
            }
        }
        self.tx.commit().await?;
        Ok(ChannelCommandCommit {
            source: source.0,
            inserted: true,
            notices: stored_notices,
        })
    }
}
