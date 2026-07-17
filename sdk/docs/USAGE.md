# ZKas SDK Usage

## Packages

- `zkas-sdk`: application-facing facade, BlockDAG sync contracts, storage,
  addresses, prepared-payment wire format, and wallet state.
- `zkas-wallet-engine`: deterministic note/chunk selection and dynamic fee policy.
- `zkas-signer`: software key custody and anti-blind Orchard authorization.

Applications should normally depend only on `zkas-sdk`.

## Create a signer and address

```rust
use zkas_sdk::{Network, ShieldedAddress, SoftwareSigner};

let signer = SoftwareSigner::new(seed_bytes)?;
let address = ShieldedAddress::from_raw(&Network::Mainnet, signer.address_bytes())?;
```

The seed stays in `SoftwareSigner` and is zeroized when dropped. Persist seeds in
the platform keystore, not in SDK snapshots or application logs.

## Synchronize

Implement `ChainSource` for the node/light service and `WalletStore` for the
platform database, then create `Wallet::from_seed` or `Wallet::from_viewing_key`.
Call `sync_once` until the source returns no settled blocks.

`MemoryStore` is for tests. `FileStore` provides atomic, permission-restricted
snapshots for CLI/desktop applications. Mobile/browser applications should
implement `WalletStore` over their transactional platform database or IndexedDB.

ZKas sync semantics differ from ordinary linear chains:

- `after` is a selected-chain block hash, not a numeric height;
- blocks are supplied in GHOSTDAG accepted order;
- the SDK holds back blocks within `settlementBlueScore` of the sink;
- an explicit `reorged` result stops ingestion before corrupting the append-only
  Orchard witness tree;
- the wallet checkpoint and selected-chain cursor are stored atomically;
- a pruning-point rescan/frontier recovery must be an explicit application policy.

## Hosted non-custodial payment

1. The local signer derives an FVK and registers a watch-only wallet.
2. Walletd scans, selects matured notes, builds the Halo 2 proof, and returns
   `preparedPayment` from `/prepare`.
3. Deserialize it with `PreparedPaymentV1::to_typed`.
4. Construct `PaymentIntent` from the recipient, integer amount, and maximum fee
   that the user actually approved—not values copied from the server.
5. Call `SoftwareSigner::verify_and_sign` with the locally configured genesis.
6. Return the indexed signatures to `/submit`.

The envelope checksum detects transport/storage corruption. Security does not
depend on that checksum: the signer independently checks note/value commitments,
recipient, amount, fee, change, network domain, action indices, and recomputed
sighash before signing.

## Amounts

Use `u64` in Rust. JSON/TypeScript boundaries represent sompi amounts as decimal
strings or `bigint`; never use floating point for payment construction.

## Examples

```bash
cargo run -p zkas-sdk --example payment_plan
cargo run -p zkas-sdk --example sign_prepared_payment -- \
  prepared.json SEED_HEX zkas:ADDRESS AMOUNT_SOMPI FEE_SOMPI
```
