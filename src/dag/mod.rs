//! A DAG, or directed acyclic graph, allows us to represent our identity as an
//! ordered list of signed changes, as opposed to a singular object. There are
//! pros and cons to both methods, but for the purposes of this project, a
//! tree of signed transactions that link back to previous changes provides a
//! good amount of security, auditability, and syncability.

mod transaction;
mod transactions;

pub use crate::dag::{
    transaction::{
        TransactionBody,
        TransactionID,
        TransactionEntry,
        Transaction,
    },
    transactions::{
        Transactions,
    },
};

