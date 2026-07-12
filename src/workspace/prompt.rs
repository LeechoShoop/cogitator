//! TUI prompt state machine for workspace actions.

use std::path::PathBuf;

/// The types of workspace actions that require a secret prompt or confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingWorkspaceAction {
    /// Pending load of a workspace from a file.
    Load(PathBuf),
    /// Pending save of a workspace to a file.
    Save(PathBuf),
    /// No action is pending.
    None,
}

impl Default for PendingWorkspaceAction {
    fn default() -> Self {
        Self::None
    }
}

/// The state of the secret prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingSecretPrompt {
    /// Prompting for a passphrase.
    Prompting {
        action: PendingWorkspaceAction,
        buffer: String,
    },
    /// No prompt is active.
    Inactive,
}

impl Default for PendingSecretPrompt {
    fn default() -> Self {
        Self::Inactive
    }
}

/// A state machine for the workspace prompt flow.
#[derive(Debug, Default)]
pub struct WorkspacePromptState {
    pub action: PendingWorkspaceAction,
    pub secret_prompt: PendingSecretPrompt,
}

impl WorkspacePromptState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin an action that might require a passphrase.
    pub fn begin_action(&mut self, action: PendingWorkspaceAction) {
        self.action = action;
        self.secret_prompt = PendingSecretPrompt::Prompting {
            action: self.action.clone(),
            buffer: String::new(),
        };
    }

    /// Complete the prompt and return the gathered passphrase and action.
    pub fn complete(&mut self) -> Option<(PendingWorkspaceAction, String)> {
        match std::mem::take(&mut self.secret_prompt) {
            PendingSecretPrompt::Prompting { action, buffer } => {
                self.action = PendingWorkspaceAction::None;
                Some((action, buffer))
            }
            PendingSecretPrompt::Inactive => None,
        }
    }

    /// Cancel the current prompt.
    pub fn cancel(&mut self) {
        self.action = PendingWorkspaceAction::None;
        self.secret_prompt = PendingSecretPrompt::Inactive;
    }
}
