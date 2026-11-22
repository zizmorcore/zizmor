//! Deferred YAML fixes using Astral's transactional editor.

use std::borrow::Cow;

use astral_yaml_serde::{
    EditableYaml, Value,
    edit::{CommentPlacement, Cursor, NodeKind},
};
use thiserror::Error;
use yamlpath::{Component, Document, Route};

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Yaml(#[from] astral_yaml_serde::Error),
    #[error("{0}")]
    InvalidOperation(String),
}

/// A route and an operation to apply at that route.
#[derive(Debug, Clone)]
pub struct Patch<'doc> {
    /// The route to the feature to patch.
    pub route: Route<'doc>,
    /// The operation to perform on the feature.
    pub operation: Op<'doc>,
}

/// Represents a YAML patch operation.
#[derive(Debug, Clone)]
pub enum Op<'doc> {
    /// Replace the first matching fragment in the decoded string at this route.
    RewriteString {
        from: subfeature::Subfeature<'doc>,
        to: Cow<'doc, str>,
    },
    /// Replace an existing inline comment on the selected node.
    ReplaceComment { new: Cow<'doc, str> },
    /// Emplace a comment at the given path.
    ///
    /// This is like `ReplaceComment`, but will insert a new comment
    /// if none exists.
    EmplaceComment { new: Cow<'doc, str> },
    /// Replace the value at the given path
    Replace(Value),
    /// Add a new key-value pair at the given path.
    ///
    /// The route should point to a mapping.
    ///
    /// The key must be absent.
    Add { key: String, value: Value },
    /// Set a field in a child mapping, creating the mapping if it is missing or null.
    SetField {
        mapping: &'doc str,
        key: String,
        value: Value,
    },
    /// Remove a mapping entry or a sequence item at its use site.
    Remove,
}

/// Apply the edits in a single transaction and return Astral's rendered YAML.
pub fn apply_yaml_patches(document: &Document, patches: &[Patch<'_>]) -> Result<String, Error> {
    let mut editor = EditableYaml::parse(document.source())?;
    editor.try_edit(|mut root| {
        for patch in patches {
            patch.apply(root.reborrow(), document)?;
        }
        Ok::<_, Error>(())
    })?;
    Ok(editor.into_yaml())
}

impl Patch<'_> {
    fn apply(&self, root: Cursor<'_, '_>, document: &Document) -> Result<(), Error> {
        let path = self.route.components();
        match &self.operation {
            Op::Remove => {
                let (last, parent) = path.split_last().ok_or_else(|| {
                    Error::InvalidOperation("cannot remove the document root".into())
                })?;
                let mut parent = select(root, parent, document)?;
                expand_alias(&mut parent)?;
                match last {
                    Component::Key(name) => {
                        if !parent.into_mapping()?.remove(name)? {
                            return Err(Error::InvalidOperation(format!("no such key: {name}")));
                        }
                    }
                    Component::Index(i) => parent.into_sequence()?.remove(*i)?,
                }
            }
            Op::Replace(value) => select(root, path, document)?.set(value)?,
            Op::RewriteString { from, to } => {
                let mut cursor = select(root, path, document)?;
                let mut string = cursor.read::<String>()?;
                let span = from
                    .locate_within(&string)
                    .ok_or_else(|| Error::InvalidOperation(format!("no match for {from:?}")))?;
                string.replace_range(span.as_range(), to);
                cursor.set(string)?;
            }
            Op::Add { key, value } => {
                let mut mapping = mapping(root, path, document)?;
                let entry = mapping.entry(key)?;
                if entry.is_occupied() {
                    return Err(Error::InvalidOperation(format!(
                        "key '{key}' already exists"
                    )));
                }
                entry.or_insert(value)?;
            }
            Op::SetField {
                mapping: name,
                key,
                value,
            } => {
                let mut parent = mapping(root, path, document)?;
                let empty = Value::Mapping(Vec::new());
                let mut field = parent.entry(name)?.or_insert(&empty)?;
                check_anchor(&field, document)?;
                expand_alias(&mut field)?;
                if matches!(field.node()?.kind(), NodeKind::Scalar { .. })
                    && field.read::<Value>()? == Value::Null
                {
                    field.set(empty)?;
                }
                let mut mapping = field.into_mapping()?;
                if let Some(target) = mapping.get(key)? {
                    check_anchor(&target, document)?;
                }
                mapping.set(key, value)?;
            }
            Op::ReplaceComment { new } | Op::EmplaceComment { new } => {
                let mut cursor = select(root, path, document)?;
                let text = new.strip_prefix('#').ok_or_else(|| {
                    Error::InvalidOperation("a YAML comment starts with '#'".into())
                })?;
                let mut comments = cursor
                    .node()?
                    .comments()
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.placement() == CommentPlacement::Inline);
                match (comments.next(), comments.next()) {
                    (Some((i, _)), None) => cursor.replace_comment(i, text)?,
                    (None, _) if matches!(self.operation, Op::EmplaceComment { .. }) => {
                        cursor.append_comment(text, CommentPlacement::Inline)?
                    }
                    (None, _) => {}
                    _ => {
                        return Err(Error::InvalidOperation(
                            "multiple inline comments on selected node".into(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn mapping<'edit, 'doc>(
    root: Cursor<'edit, 'doc>,
    path: &[Component<'_>],
    document: &Document,
) -> Result<astral_yaml_serde::edit::MappingMut<'edit, 'doc>, Error> {
    let mut cursor = select(root, path, document)?;
    expand_alias(&mut cursor)?;
    Ok(cursor.into_mapping()?)
}

fn select<'edit, 'doc>(
    mut cursor: Cursor<'edit, 'doc>,
    path: &[Component<'_>],
    document: &Document,
) -> Result<Cursor<'edit, 'doc>, Error> {
    check_anchor(&cursor, document)?;
    for component in path {
        expand_alias(&mut cursor)?;
        cursor = match component {
            Component::Key(key) => cursor.field(key)?,
            Component::Index(i) => cursor.item(*i)?,
        };
        check_anchor(&cursor, document)?;
    }
    Ok(cursor)
}

// Editing through an alias changes that use site independently of other users.
fn expand_alias(cursor: &mut Cursor<'_, '_>) -> Result<(), Error> {
    if matches!(cursor.node()?.kind(), NodeKind::Alias { .. }) {
        cursor.update::<Value>(std::convert::identity)?;
    }
    Ok(())
}

// Updating a definition could change an unrelated step that uses the same anchor.
fn check_anchor(cursor: &Cursor<'_, '_>, document: &Document) -> Result<(), Error> {
    if let Some(name) = cursor.node()?.anchor()
        && document.references_anchor(name)
    {
        return Err(Error::InvalidOperation(format!(
            "cannot edit shared YAML anchor &{name}"
        )));
    }
    Ok(())
}
