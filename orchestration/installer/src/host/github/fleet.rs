//! Fleet reads of the GitHub host adapter (#681): who an owner is, every
//! repository of a user or organization, and the organization's rulesets and
//! settings. A listing stopped by the rate limit or the call budget returns
//! what it read, why it stopped and how many repositories it did not read;
//! a listing over the page cap is `Truncated`, never a silent partial result.
use super::{GitHub, HostResult, flag, number, opt_text, ruleset, shape, text, visibility};
use crate::{
    host::{
        HostError, HostErrorKind, HostKind, OwnerId, OwnerKind, Partial, RepoId, authorize,
        types::{OrgSettings, RepoSummary, Ruleset},
    },
    remote::segment,
};
use serde_json::Value;

/// Full pages of a repository listing read before it is `Truncated` (10 000 repositories).
pub const FLEET_PAGE_CAP: u32 = 100;
const PER_PAGE: usize = 100;

/// The read gate for an owner name, as a host error before any call.
fn gate(name: &str) -> HostResult<()> {
    authorize::read_owner(name).map_err(|e| HostError::new(HostErrorKind::Forbidden, e.to_string()))
}

/// The sum of the counts GitHub showed, `None` when any of them was not visible.
fn count(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().map(|k| value[*k].as_u64()).sum()
}

impl GitHub<'_> {
    pub(super) fn read_owner(&self, name: &str) -> HostResult<OwnerId> {
        gate(name)?;
        let what = format!("owner {name}");
        let v = self.get(&what, &format!("users/{}", segment(name)))?;
        let kind = match v["type"].as_str() {
            Some("User") => OwnerKind::User,
            Some("Organization") => OwnerKind::Organization,
            _ => OwnerKind::Unknown,
        };
        Ok(OwnerId {
            host: HostKind::GitHub,
            name: text(&v, "login", &what)?.to_lowercase(),
            kind,
        })
    }

    /// The endpoint and the repository count for `owner`. `users/{u}/repos`
    /// lists public repositories only, so the authenticated user's own listing
    /// reads `user/repos` instead, which includes the private ones.
    fn listing(&self, owner: &OwnerId, what: &str) -> HostResult<(String, Option<u64>)> {
        let name = segment(&owner.name);
        let kind = match owner.kind {
            OwnerKind::Unknown => self.read_owner(&owner.name)?.kind,
            kind => kind,
        };
        match kind {
            OwnerKind::Organization => {
                let org = self.get(what, &format!("orgs/{name}"))?;
                Ok((
                    format!("orgs/{name}/repos?type=all"),
                    count(&org, &["public_repos", "total_private_repos"]),
                ))
            }
            OwnerKind::User => {
                let me = self.get(what, "user")?;
                if me["login"]
                    .as_str()
                    .is_some_and(|l| l.eq_ignore_ascii_case(&owner.name))
                {
                    return Ok((
                        "user/repos?affiliation=owner".to_owned(),
                        count(&me, &["public_repos", "owned_private_repos"]),
                    ));
                }
                let user = self.get(what, &format!("users/{name}"))?;
                Ok((
                    format!("users/{name}/repos?type=owner"),
                    count(&user, &["public_repos"]),
                ))
            }
            OwnerKind::Unknown => Err(HostError::new(
                HostErrorKind::Unsupported,
                format!(
                    "{} is neither a user nor an organization, so its repositories cannot be listed",
                    owner.name
                ),
            )),
        }
    }

    pub(super) fn repositories(&self, owner: &OwnerId) -> HostResult<Partial<RepoSummary>> {
        gate(&owner.name)?;
        let what = format!("repositories of {}", owner.name);
        let (path, expected) = self.listing(owner, &what)?;
        let mut listed: Vec<Value> = Vec::new();
        let mut stopped = None;
        let mut capped = true;
        for page in 1..=FLEET_PAGE_CAP {
            let batch = match self.get(&what, &format!("{path}&per_page=100&page={page}")) {
                Ok(v) => v
                    .as_array()
                    .cloned()
                    .ok_or_else(|| shape(&what, "the response is not a list"))?,
                Err(e) if matches!(e.kind, HostErrorKind::RateLimited { .. }) => {
                    stopped = Some((page, e));
                    break;
                }
                Err(e) => return Err(e),
            };
            let full = batch.len() >= PER_PAGE;
            listed.extend(batch);
            if !full {
                capped = false;
                break;
            }
        }
        if capped && stopped.is_none() {
            return Err(HostError::new(
                HostErrorKind::Truncated,
                format!(
                    "{what} has more than {} items, the page cap of this read",
                    FLEET_PAGE_CAP as usize * PER_PAGE
                ),
            ));
        }
        let mut items = Vec::new();
        let mut refused = 0;
        let mut refused_word: Option<String> = None;
        for r in &listed {
            let full_name = text(r, "full_name", &what)?;
            if let Some(word) = crate::config::denied_word(&full_name)
                .map_err(|e| HostError::new(HostErrorKind::Forbidden, e.to_string()))?
            {
                refused_word.get_or_insert(word);
                refused += 1;
                continue;
            }
            items.push(summary(r, &full_name, &what)?);
        }
        items.sort_by(|a, b| a.id.cmp(&b.id));
        let mut unread = Vec::new();
        if refused > 0 {
            unread.push(format!(
                "{refused} repositories not read: {} identities are refused by the read gate",
                refused_word.as_deref().unwrap_or("Denylisted")
            ));
        }
        if let Some((page, _)) = &stopped {
            let read = listed.len() as u64;
            unread.push(match expected {
                Some(total) if total > read => format!(
                    "{} repositories not read: {} from page {page} on",
                    total - read,
                    owner.name
                ),
                _ => format!(
                    "repositories of {} from page {page} on not read (count unknown)",
                    owner.name
                ),
            });
        }
        Ok(Partial {
            items,
            stopped: stopped.map(|(_, e)| e),
            unread,
        })
    }

    /// The list endpoint carries no rules, so each ruleset costs one more read.
    pub(super) fn organization_rulesets(&self, org: &str) -> HostResult<Vec<Ruleset>> {
        gate(org)?;
        let base = format!("orgs/{}", segment(org));
        let what = format!("organization rulesets of {org}");
        let list = self
            .list(&what, &format!("{base}/rulesets"), None)
            .map_err(|e| match e.kind {
                HostErrorKind::Forbidden => HostError::new(
                    HostErrorKind::Forbidden,
                    format!(
                        "{what} are unavailable: organization rulesets need the Team plan or admin ({})",
                        e.message
                            .strip_prefix(&format!("Reading {what} is forbidden ("))
                            .and_then(|d| d.strip_suffix(')'))
                            .unwrap_or(&e.message)
                    ),
                ),
                _ => e,
            })?;
        list.iter()
            .map(|summary| {
                let id = number(summary, "id", &what)?;
                ruleset(&self.get(&what, &format!("{base}/rulesets/{id}"))?, &what)
            })
            .collect()
    }

    /// The organization's owners, by login (#1218): its members whose role is
    /// `admin`. Readable by the organization's members.
    pub(super) fn organization_owners(&self, org: &str) -> HostResult<Vec<String>> {
        gate(org)?;
        let what = format!("owners of organization {org}");
        self.list(
            &what,
            &format!("orgs/{}/members?role=admin", segment(org)),
            None,
        )?
        .iter()
        .map(|member| text(member, "login", &what))
        .collect()
    }

    /// `GET orgs/{o}`: a field the token cannot see stays `None`, never `false`.
    pub(super) fn organization_settings(&self, org: &str) -> HostResult<OrgSettings> {
        gate(org)?;
        let v = self.get(
            &format!("organization {org}"),
            &format!("orgs/{}", segment(org)),
        )?;
        Ok(OrgSettings {
            two_factor_requirement_enabled: v["two_factor_requirement_enabled"].as_bool(),
            default_repository_permission: opt_text(&v["default_repository_permission"]),
            members_can_create_public_repositories: v["members_can_create_public_repositories"]
                .as_bool(),
            plan_hint: opt_text(&v["plan"]["name"]),
            web_commit_signoff_required: v["web_commit_signoff_required"].as_bool(),
        })
    }
}

fn summary(r: &Value, full_name: &str, what: &str) -> HostResult<RepoSummary> {
    Ok(RepoSummary {
        id: RepoId::parse(full_name)
            .map_err(|_| shape(what, &format!("{full_name} is not owner/name")))?,
        visibility: visibility(r, what)?,
        default_branch: text(r, "default_branch", what)?,
        archived: flag(r, "archived", what)?,
        fork: flag(r, "fork", what)?,
        pushed_at: opt_text(&r["pushed_at"]),
        language: opt_text(&r["language"]),
    })
}
