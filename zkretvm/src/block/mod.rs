use std::{
    fmt,
    io::{self, Error, ErrorKind},
};

use crate::state;
use avalanche_types::{
    choices, ids,
    subnet::rpc::consensus::snowman::{self, Decidable},
};
use chrono::{Duration, Utc};
use derivative::{self, Derivative};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

pub mod transaction;
use transaction::Transaction;

/// Represents a block, specific to [`Vm`](crate::vm::Vm).
#[serde_as]
#[derive(Serialize, Deserialize, Clone, Derivative, Default)]
#[derivative(Debug, PartialEq, Eq)]
pub struct Block {
    /// The block Id of the parent block.
    parent_id: ids::Id,
    /// This block's height.
    /// The height of the genesis block is 0.
    height: u64,
    /// Unix second when this block was proposed.
    timestamp: u64,

    transaction: Transaction,

    /// Current block status.
    #[serde(skip)]
    status: choices::status::Status,
    /// This block's encoded bytes.
    #[serde(skip)]
    bytes: Vec<u8>,
    /// Generated block Id.
    #[serde(skip)]
    id: ids::Id,

    /// Reference to the Vm state manager for blocks.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    #[serde(skip)]
    state: state::State,
}

impl Block {
    /// Can fail if the block can't be serialized to JSON.
    /// # Errors
    /// Will fail if the block can't be serialized to JSON.
    pub fn try_new(
        parent_id: ids::Id,
        height: u64,
        timestamp: u64,
        transaction: Transaction,
        status: choices::status::Status,
    ) -> io::Result<Self> {
        let mut b = Self {
            parent_id,
            height,
            timestamp,
            transaction,
            ..Default::default()
        };

        b.status = status;
        b.bytes = b.to_vec()?;
        b.id = ids::Id::sha256(&b.bytes);

        Ok(b)
    }

    /// # Errors
    /// Can fail if the block can't be serialized to JSON.
    pub fn to_json_string(&self) -> io::Result<String> {
        serde_json::to_string(&self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Block to JSON string {e}"),
            )
        })
    }

    /// Encodes the [`Block`](Block) to JSON in bytes.
    /// # Errors
    /// Errors if the block can't be serialized to JSON.
    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(&self).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to serialize Block to JSON bytes {e}"),
            )
        })
    }

    /// Loads [`Block`](Block) from JSON bytes.
    /// # Errors
    /// Will fail if the block can't be deserialized from JSON.
    pub fn from_slice(d: impl AsRef<[u8]>) -> io::Result<Self> {
        let dd = d.as_ref();
        let mut b: Self = serde_json::from_slice(dd).map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("failed to deserialize Block from JSON {e}"),
            )
        })?;

        b.bytes = dd.to_vec();
        b.id = ids::Id::sha256(&b.bytes);

        Ok(b)
    }

    /// Returns the parent block Id.
    #[must_use]
    pub fn parent_id(&self) -> ids::Id {
        self.parent_id
    }

    /// Returns the height of this block.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Returns the timestamp of this block.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[must_use]
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Returns the status of this block.
    #[must_use]
    pub fn status(&self) -> choices::status::Status {
        self.status.clone()
    }

    /// Updates the status of this block.
    pub fn set_status(&mut self, status: choices::status::Status) {
        self.status = status;
    }

    /// Returns the byte representation of this block.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the ID of this block
    #[must_use]
    pub fn id(&self) -> ids::Id {
        self.id
    }

    /// Updates the state of the block.
    pub fn set_state(&mut self, state: state::State) {
        self.state = state;
    }

    /// Verifies [`Block`](Block) properties (e.g., heights),
    /// and once verified, records it to the [`State`](crate::state::State).
    /// # Errors
    /// Can fail if the parent block can't be retrieved.
    pub async fn verify(&mut self) -> io::Result<()> {
        if self.height == 0 && self.parent_id == ids::Id::empty() {
            log::debug!(
                "block {} has an empty parent Id since it's a genesis block -- skipping verify",
                self.id
            );
            self.state.add_verified(&self.clone()).await;
            return Ok(());
        }

        // if already exists in database, it means it's already accepted
        // thus no need to verify once more
        if self.state.get_block(&self.id).await.is_ok() {
            log::debug!("block {} already verified", self.id);
            return Ok(());
        }

        // linear chain
        let last_accepted_id = self.state.get_last_accepted_block_id().await?;
        if self.parent_id != last_accepted_id {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "parent block id {} != last accepted block id {}",
                    self.parent_id, last_accepted_id
                ),
            ));
        }

        let prnt_blk = self.state.get_block(&self.parent_id).await?;

        // ensure the height of the block is immediately following its parent
        if prnt_blk.height != self.height - 1 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "parent block height {} != current block height {} - 1",
                    prnt_blk.height, self.height
                ),
            ));
        }

        // ensure block timestamp is after its parent
        if prnt_blk.timestamp > self.timestamp {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "parent block timestamp {} > current block timestamp {}",
                    prnt_blk.timestamp, self.timestamp
                ),
            ));
        }

        let one_hour_from_now = Utc::now() + Duration::hours(1);
        let one_hour_from_now = one_hour_from_now
            .timestamp()
            .try_into()
            .expect("failed to convert timestamp from i64 to u64");

        // ensure block timestamp is no more than an hour ahead of this nodes time
        if self.timestamp >= one_hour_from_now {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "block timestamp {} is more than 1 hour ahead of local time",
                    self.timestamp
                ),
            ));
        }

        let merkle_leaves = self.state.get_merkle_leaves().await?;
        let nullifiers = self.state.get_nullifiers().await?;
        let unclaimed_pub_keys = self.state.get_unclaimed_pub_keys().await?;
        let revealed_pub_keys = self.state.get_revealed_pub_keys().await?;

        if !self.transaction.verify(
            &merkle_leaves,
            &nullifiers,
            &unclaimed_pub_keys,
            &revealed_pub_keys,
        ) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("block {} transaction is invalid", self.id),
            ));
        }

        // add newly verified block to memory
        self.state.add_verified(&self.clone()).await;
        Ok(())
    }

    /// Mark this [`Block`](Block) accepted and updates [`State`](crate::state::State) accordingly.
    /// # Errors
    /// Returns an error if the state can't be updated.
    pub async fn accept(&mut self) -> io::Result<()> {
        self.set_status(choices::status::Status::Accepted);

        let mut merkle_leaves = self.state.get_merkle_leaves().await?;
        let mut nullifiers = self.state.get_nullifiers().await?;
        let mut unclaimed_pub_keys = self.state.get_unclaimed_pub_keys().await?;
        let mut revealed_pub_keys = self.state.get_revealed_pub_keys().await?;

        self.transaction.update_state(
            &mut merkle_leaves,
            &mut nullifiers,
            &mut unclaimed_pub_keys,
            &mut revealed_pub_keys,
        );

        self.state.set_merkle_leaves(&merkle_leaves).await?;
        self.state.set_nullifiers(&nullifiers).await?;
        self.state
            .set_unclaimed_pub_keys(&unclaimed_pub_keys)
            .await?;
        self.state.set_revealed_pub_keys(&revealed_pub_keys).await?;

        // only decided blocks are persistent -- no reorg
        self.state.write_block(&self.clone()).await?;
        self.state.set_last_accepted_block(&self.id()).await?;

        // self.state.remove_verified(&self.id()).await;
        self.state.clear_verified().await;
        Ok(())
    }

    /// Mark this [`Block`](Block) rejected and updates [`State`](crate::state::State) accordingly.
    /// # Errors
    /// Returns an error if the state can't be updated.
    pub async fn reject(&mut self) -> io::Result<()> {
        self.set_status(choices::status::Status::Rejected);

        // only decided blocks are persistent -- no reorg
        self.state.write_block(&self.clone()).await?;

        self.state.remove_verified(&self.id()).await;
        Ok(())
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serialized = self.to_json_string().unwrap();
        write!(f, "{serialized}")
    }
}

#[tonic::async_trait]
impl snowman::Block for Block {
    async fn bytes(&self) -> &[u8] {
        return self.bytes.as_ref();
    }

    async fn height(&self) -> u64 {
        self.height
    }

    async fn timestamp(&self) -> u64 {
        self.timestamp
    }

    async fn parent(&self) -> ids::Id {
        self.parent_id
    }

    async fn verify(&mut self) -> io::Result<()> {
        self.verify().await
    }
}

#[tonic::async_trait]
impl Decidable for Block {
    /// Implements "snowman.Block.choices.Decidable"
    async fn status(&self) -> choices::status::Status {
        self.status.clone()
    }

    async fn id(&self) -> ids::Id {
        self.id
    }

    async fn accept(&mut self) -> io::Result<()> {
        self.accept().await
    }

    async fn reject(&mut self) -> io::Result<()> {
        self.reject().await
    }
}
