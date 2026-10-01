#![doc = "Pure deterministic Zero Trust policy evaluation for Crowsi."]

mod checks;
mod evaluate;
mod freshness;
mod model;
mod output;
mod policy;
mod time;

pub use evaluate::evaluate;
pub use model::{
    AuthorityState, EvaluationInput, IncidentInput, IncidentState, ManagementAuthorityInput,
    Obligation, PipInput, PolicyEvaluation, PolicyInput, PostureInput, PostureState, ReasonCode,
    TrustWindow,
};

pub use crowsi_control_contracts::{AssuranceLevel, DecisionEffect};
