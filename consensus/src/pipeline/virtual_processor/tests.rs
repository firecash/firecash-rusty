use crate::{consensus::test_consensus::TestConsensus, model::services::reachability::ReachabilityService};
use kaspa_consensus_core::{
    BlockHashSet,
    api::ConsensusApi,
    block::{Block, BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockhash,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    config::{
        ConfigBuilder,
        params::{ForkActivation, MAINNET_PARAMS},
    },
    constants::{BLOCK_VERSION, TOCCATA_BLOCK_VERSION},
    tx::{ScriptPublicKey, ScriptVec, Transaction},
};
use kaspa_hashes::Hash;
use std::{collections::VecDeque, thread::JoinHandle};

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs) }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap()
    }

    fn reject_selection(&mut self, _tx_id: kaspa_consensus_core::tx::TransactionId) {
        unimplemented!()
    }

    fn is_successful(&self) -> bool {
        true
    }
}

struct TestContext {
    consensus: TestConsensus,
    join_handles: Vec<JoinHandle<()>>,
    miner_data: MinerData,
    simulated_time: u64,
    current_templates: VecDeque<BlockTemplate>,
    current_tips: BlockHashSet,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.consensus.shutdown(std::mem::take(&mut self.join_handles));
    }
}

impl TestContext {
    fn new(consensus: TestConsensus) -> Self {
        let join_handles = consensus.init();
        let genesis_hash = consensus.params().genesis.hash;
        let simulated_time = consensus.params().genesis.timestamp;
        Self {
            consensus,
            join_handles,
            miner_data: new_miner_data(),
            simulated_time,
            current_templates: Default::default(),
            current_tips: BlockHashSet::from_iter([genesis_hash]),
        }
    }

    pub fn build_block_template_row(&mut self, nonces: impl Iterator<Item = usize>) -> &mut Self {
        for nonce in nonces {
            self.simulated_time += self.consensus.params().target_time_per_block();
            self.current_templates.push_back(self.build_block_template(nonce as u64, self.simulated_time));
        }
        self
    }

    pub fn assert_row_parents(&mut self) -> &mut Self {
        for t in self.current_templates.iter() {
            assert_eq!(self.current_tips, BlockHashSet::from_iter(t.block.header.direct_parents().iter().copied()));
        }
        self
    }

    pub async fn validate_and_insert_row(&mut self) -> &mut Self {
        self.current_tips.clear();
        while let Some(t) = self.current_templates.pop_front() {
            self.current_tips.insert(t.block.header.hash);
            self.validate_and_insert_block(t.block.to_immutable()).await;
        }
        self
    }

    pub async fn build_and_insert_disqualified_chain(&mut self, mut parents: Vec<Hash>, len: usize) -> Hash {
        // The chain will be disqualified since build_block_with_parents builds utxo-invalid blocks
        for _ in 0..len {
            self.simulated_time += self.consensus.params().target_time_per_block();
            let b = self.build_block_with_parents(parents, 0, self.simulated_time);
            parents = vec![b.header.hash];
            self.validate_and_insert_block(b.to_immutable()).await;
        }
        parents[0]
    }

    pub fn build_block_template(&self, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(
                self.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_block_with_parents(&self, parents: Vec<Hash>, nonce: u64, timestamp: u64) -> MutableBlock {
        let mut b = self.consensus.build_block_with_parents_and_transactions(blockhash::NONE, parents, Default::default());
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize(); // This overrides the NONE hash we passed earlier with the actual hash
        b
    }

    pub async fn validate_and_insert_block(&mut self, block: Block) -> &mut Self {
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
        self
    }

    pub fn assert_tips(&mut self) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()), self.current_tips);
        self
    }

    pub fn assert_tips_num(&mut self, expected_num: usize) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()).len(), expected_num);
        self
    }

    pub fn assert_virtual_parents_subset(&mut self) -> &mut Self {
        assert!(self.consensus.get_virtual_parents().is_subset(&self.current_tips));
        self
    }

    pub fn assert_valid_utxo_tip(&mut self) -> &mut Self {
        // Assert that at least one body tip was resolved with valid UTXO
        assert!(self.consensus.body_tips().iter().copied().any(|h| self.consensus.block_status(h) == BlockStatus::StatusUTXOValid));
        self
    }

    /// Build a template on the current virtual tips and grind a REAL FishHashPlus
    /// nonce for it (no skip_proof_of_work). At the easiest target this is 1-2
    /// hashes. Returns the mined, finalized block.
    fn mine_real_pow_block(&mut self) -> Block {
        self.mine_real_pow_block_with(Default::default())
    }

    /// As `mine_real_pow_block`, but includes the given transactions (a miner
    /// picking them up from the mempool).
    fn mine_real_pow_block_with(&mut self, txs: Vec<Transaction>) -> Block {
        self.simulated_time += self.consensus.params().target_time_per_block();
        let mut t = self
            .consensus
            .build_block_template(self.miner_data.clone(), Box::new(OnetimeTxSelector::new(txs)), TemplateBuildMode::Standard)
            .unwrap();
        t.block.header.timestamp = self.simulated_time;
        let state = kaspa_pow::State::new(&t.block.header);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t.block.to_immutable()
    }
}

/// LIVE real-PoW proof: mine a chain of blocks whose PoW is the actual
/// FishHashPlus (KarlsenHashV2) — no `skip_proof_of_work` — while paying a
/// shielded (Orchard) coinbase. Every block's header goes through the real
/// `check_pow` path in the pipeline, so reaching UTXOValid means the fishhash
/// PoW verifies on real blocks AND the shielded coinbase mints into the pool.
/// This is the first test that exercises FishHashPlus in consensus for real; all
/// others skip PoW. Uses the easiest target (0x207fffff) so CPU grinding is ~1-2
/// hashes; run in release so the light cache builds in ~3s.
#[tokio::test]
async fn real_fishhash_pow_mines_shielded_chain_live() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    // Real PoW (skip_proof_of_work stays false) but trivial difficulty seeded from
    // an easy genesis target, so a nonce is found almost immediately.
    let config = ConfigBuilder::new(params).edit_consensus_params(|p| p.genesis.bits = 0x207fffff).build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("valid orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    let mut tips = BlockHashSet::from_iter([config.genesis.hash]);
    for _ in 0..4 {
        let block = ctx.mine_real_pow_block();
        assert_eq!(tips, BlockHashSet::from_iter(block.header.direct_parents().iter().copied()), "extends the single chain");
        tips = BlockHashSet::from_iter([block.header.hash]);
        let status = ctx.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.is_utxo_valid_or_pending(), "real-PoW shielded block must be accepted");
    }

    // The chain tip is UTXO-valid: real FishHashPlus verified every header and the
    // shielded coinbase advanced the pool anchor past the empty tree.
    ctx.assert_valid_utxo_tip();
    let empty_anchor = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let vp = ctx.consensus.virtual_processor();
    let advanced = ctx
        .consensus
        .body_tips()
        .iter()
        .copied()
        .filter(|h| ctx.consensus.block_status(*h) == BlockStatus::StatusUTXOValid)
        .filter_map(|h| vp.shielded_anchor_at(h).ok())
        .any(|anchor| anchor != empty_anchor);
    assert!(advanced, "shielded coinbase mined under real FishHashPlus must advance the anchor");
}

#[tokio::test]
async fn diag_shielded_coinbase_note_structure() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).unwrap();
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    let empty = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let mut parent = config.genesis.hash;
    for i in 0..6u64 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block();
        let mut t = ctx
            .consensus
            .build_block_template(ctx.miner_data.clone(), Box::new(OnetimeTxSelector::new(Default::default())), TemplateBuildMode::Standard)
            .unwrap();
        t.block.header.timestamp = ctx.simulated_time;
        t.block.header.finalize();
        let cb_outs = t.block.transactions[0].outputs.len();
        let cb_out_values: Vec<u64> = t.block.transactions[0].outputs.iter().map(|o| o.value).collect();
        let h = t.block.header.hash;
        ctx.consensus.validate_and_insert_block(t.block.to_immutable()).virtual_state_task.await.unwrap();
        let anchor = ctx.consensus.virtual_processor().shielded_anchor_at(h).ok();
        println!(
            "block {i} hash={h} cb_outputs={cb_outs} values={cb_out_values:?} anchor_advanced={} parent={parent}",
            anchor.map(|a| a != empty).unwrap_or(false)
        );
        parent = h;
    }
}

#[tokio::test]
async fn template_mining_sanity_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let rounds = 10;
    let width = 3;
    for _ in 0..rounds {
        ctx.build_block_template_row(0..width)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_virtual_parents_subset()
            .assert_valid_utxo_tip();
    }
}

/// LIVE proof of the shielded coinbase (PLAN §2.7): with `shielded_coinbase`
/// enabled, mine a row of real blocks whose coinbase pays a shielded (Orchard)
/// address, run them through the real virtual processor, and require the tip to
/// be UTXO-valid. Reaching UTXOValid means every block's coinbase reward was
/// successfully turned into coinbase notes and minted into the shielded pool
/// (a malformed recipient or a turnstile violation would yield InvalidShieldedState
/// and the block would not be UTXO-valid). No transparent coinbase value is created.
#[tokio::test]
async fn shielded_coinbase_mints_into_the_pool_live() {
    // kasprivate main params with the shielded coinbase turned on.
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params).skip_proof_of_work().build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    // The miner is paid in the shielded pool: its reward "script_public_key" is a
    // real 43-byte Orchard address (what a kasprivate miner reports).
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("valid orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    for _ in 0..5 {
        ctx.build_block_template_row(0..3)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_valid_utxo_tip();
    }

    // Directly prove value entered the pool: a UTXO-valid chain tip's shielded
    // anchor must have advanced past the empty tree (coinbase notes were appended).
    let empty_anchor = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let vp = ctx.consensus.virtual_processor();
    let advanced = ctx
        .consensus
        .body_tips()
        .iter()
        .copied()
        .filter(|h| ctx.consensus.block_status(*h) == BlockStatus::StatusUTXOValid)
        .filter_map(|h| vp.shielded_anchor_at(h).ok())
        .any(|anchor| anchor != empty_anchor);
    assert!(advanced, "shielded coinbase must have appended notes and advanced the anchor past empty");
}

/// THE end-to-end milestone (PLAN §2): under REAL FishHashPlus PoW, mine a
/// shielded-coinbase chain, then have the "wallet" build a REAL Orchard spend of
/// a mined coinbase note and push it through a mined block. The consensus layer
/// verifies the Halo 2 proof + binding/spend-auth signatures, checks the spend's
/// anchor is finalized, and applies the §2.4 transition (nullifier + turnstile).
/// This is the first fully-live private payment: mining + shielded coinbase +
/// real proof verification + state transition, all through the actual pipeline.
/// Run in release (light cache ~3s; real proof a few seconds).
#[tokio::test]
async fn real_shielded_spend_through_mined_block() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    // Real PoW at trivial difficulty; small finality so the coinbase note's anchor
    // finalizes within a short chain (spends must reference a finalized anchor).
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // Block 0 mints no note (genesis merge); block 1's coinbase mints the first and
    // only note, at tree position 0 (verified by diag_shielded_coinbase_note_structure).
    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    assert_eq!(cb.outputs.len(), 1, "block 1 coinbase is a single note at position 0");
    let cb_txid = cb.id();
    let note_value = cb.outputs[0].value;
    let anchor1 = ctx.consensus.virtual_processor().shielded_anchor_at(block1.header.hash).unwrap();

    // Mine empty blocks until block 1's anchor enters the finalized window.
    let mut guard = 0;
    while !ctx.consensus.virtual_processor().shielded_is_finalized_anchor(&anchor1).unwrap() {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
        guard += 1;
        assert!(guard < 30, "coinbase-note anchor never finalized");
    }

    // Wallet side: build a REAL proven spend of block 1's coinbase note, paying a
    // recipient (fee = 2_000). The sighash context binds to this exact tx.
    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let output_value = note_value - 2_000;
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    let payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb_txid.as_bytes(),
        0,
        note_value,
        recipient_addr,
        output_value,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.payload = payload;
    spend_tx.finalize();
    assert!(spend_tx.is_shielded(), "constructed a shielded (v2) transaction");

    // Mine a block that includes the shielded spend and validate it end-to-end.
    let spend_block = ctx.mine_real_pow_block_with(vec![spend_tx.clone()]);
    let spend_block_hash = spend_block.header.hash;
    let status = ctx.consensus.validate_and_insert_block(spend_block).virtual_state_task.await.unwrap();
    assert!(status.is_utxo_valid_or_pending(), "real shielded spend accepted: {status:?}");

    // The spend was actually included and its shielded state applied: the block is
    // UTXO-valid and its anchor advanced beyond block 1's (coinbase + spend outputs).
    assert_eq!(ctx.consensus.block_status(spend_block_hash), BlockStatus::StatusUTXOValid);
    let spend_anchor = ctx.consensus.virtual_processor().shielded_anchor_at(spend_block_hash).unwrap();
    assert_ne!(spend_anchor, anchor1, "spend block's shielded state advanced");
}

#[tokio::test]
async fn block_template_version_changes_to_v2_upon_activation() {
    let activation = MAINNET_PARAMS.genesis.daa_score + 10;
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| p.toccata_activation = ForkActivation::new(activation))
        .build();
    let consensus = TestConsensus::new(&config);
    let join_handles = consensus.init();
    let miner_data = new_miner_data();

    let mut saw_pre_activation_template = false;
    loop {
        let template = consensus
            .build_block_template(
                miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        if template.block.header.daa_score >= activation {
            assert!(saw_pre_activation_template);
            assert_eq!(template.block.header.version, TOCCATA_BLOCK_VERSION);
            break;
        }

        saw_pre_activation_template = true;
        assert_eq!(template.block.header.version, BLOCK_VERSION);
        let status = consensus.validate_and_insert_block(template.block.to_immutable()).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
    }

    consensus.shutdown(join_handles);
}

#[tokio::test]
async fn antichain_merge_test() {
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Build a large 32-wide antichain
    ctx.build_block_template_row(0..32)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mine a long enough chain s.t. the antichain is fully merged
    for _ in 0..32 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

#[tokio::test]
async fn basic_utxo_disqualified_test() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    // Mine a longer disqualified chain
    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![config.genesis.hash], 20).await;

    assert_ne!(sink, disqualified_tip);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink, disqualified_tip]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
}

#[tokio::test]
async fn double_search_disqualified_test() {
    // TODO: add non-coinbase transactions and concurrency in order to complicate the test

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.min_difficulty_window_size = p.difficulty_window_size;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine 3 valid blocks over genesis
    ctx.build_block_template_row(0..3)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mark the one expected to remain on virtual chain
    let original_sink = ctx.consensus.get_sink();

    // Find the roots to be used for the disqualified chains
    let mut virtual_parents = ctx.consensus.get_virtual_parents();
    assert!(virtual_parents.remove(&original_sink));
    let mut iter = virtual_parents.into_iter();
    let root_1 = iter.next().unwrap();
    let root_2 = iter.next().unwrap();
    assert_eq!(iter.next(), None);

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(original_sink, sink));

    // Mine a long disqualified chain
    let disqualified_tip_1 = ctx.build_and_insert_disqualified_chain(vec![root_1], 30).await;

    // And another shorter disqualified chain
    let disqualified_tip_2 = ctx.build_and_insert_disqualified_chain(vec![root_2], 20).await;

    assert_eq!(ctx.consensus.get_block_status(root_1), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_block_status(root_2), Some(BlockStatus::StatusUTXOValid));

    assert_ne!(sink, disqualified_tip_1);
    assert_ne!(sink, disqualified_tip_2);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(
        BlockHashSet::from_iter([sink, disqualified_tip_1, disqualified_tip_2]),
        BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter())
    );
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_1));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_2));

    // Mine a long enough valid chain s.t. both disqualified chains are fully merged
    for _ in 0..30 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

fn new_miner_data() -> MinerData {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (_sk, pk) = secp.generate_keypair(&mut rng);
    let script = ScriptVec::from_slice(&pk.serialize());
    MinerData::new(ScriptPublicKey::new(0, script), vec![])
}

fn inactivity_shortcut_config() -> kaspa_consensus_core::config::Config {
    ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.finality_depth = 2;
            p.toccata_activation = ForkActivation::always();
        })
        .build()
}

/// Blocks with `bs <= finality_depth` have no resolvable shortcut yet;
/// the recorded `inactivity_shortcut_block` clamps to genesis, which folds
/// to `ZERO_HASH` via `inactivity_shortcut()` and seeds forward walks
/// correctly once descendants cross `bs = finality_depth + 1`.
#[tokio::test]
async fn inactivity_shortcut_block_clamps_to_genesis_within_finality_depth() {
    let config = inactivity_shortcut_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let finality_depth = config.finality_depth();
    assert_eq!(finality_depth, 2);

    let mut chain = vec![config.genesis.hash];
    for _ in 0..2 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    for hash in chain.iter().copied().skip(1) {
        let header = ctx.consensus.get_header(hash).unwrap();
        assert!(header.blue_score <= finality_depth);
        let meta = ctx.consensus.smt_block_metadata(hash);
        assert_eq!(meta.inactivity_shortcut_block(), config.genesis.hash, "bs={}", header.blue_score);
    }
}

/// Tip at `bs = finality_depth + 4` records the chain block at
/// `bs = target_bs = tip_bs - finality_depth - 1` as its
/// inactivity_shortcut block hash.
#[tokio::test]
async fn inactivity_shortcut_resolves_to_chain_block_at_target_bs() {
    let config = inactivity_shortcut_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let finality_depth = config.finality_depth();

    let mut chain = Vec::new();
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    let tip = *chain.last().unwrap();
    let tip_header = ctx.consensus.get_header(tip).unwrap();
    assert_eq!(tip_header.blue_score, 6);
    let target_bs = tip_header.blue_score - finality_depth - 1; // = 3

    let expected_block = *chain.iter().find(|h| ctx.consensus.get_header(**h).unwrap().blue_score == target_bs).unwrap();
    let recorded = ctx.consensus.smt_block_metadata(tip).inactivity_shortcut_block();
    assert_eq!(recorded, expected_block);
}

/// Consecutive chain blocks: the inactivity_shortcut advances by one chain
/// block per parent-to-child step, since `target_bs` grows in lockstep with
/// `blue_score` on a no-merge chain.
#[tokio::test]
async fn inactivity_shortcut_advances_one_block_per_chain_step() {
    let config = inactivity_shortcut_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let mut chain = vec![config.genesis.hash];
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    for (i, hash) in chain.iter().copied().enumerate().skip(4) {
        let expected = chain[i - 3];
        assert_eq!(ctx.consensus.smt_block_metadata(hash).inactivity_shortcut_block(), expected, "block index {i}");
    }
}
