import assert from "node:assert/strict";
import { test } from "node:test";

import { DEFAULT_MAX_FEE_SOMPI, ZKasClient, ZKasSdkError, maxFeeOf } from "./client.js";
import type { PaymentSigner } from "./signer.js";
import type { DeviceSignature, PrepareResponse, PreparedPaymentEnvelope } from "./types.js";

const RECIPIENT = "zkas:qqtestrecipient";

function envelope(amount: bigint, fee: bigint): PreparedPaymentEnvelope {
  return {
    format: "zkas-prepared-payment",
    version: 2,
    networkDomain: "aa".repeat(32),
    recipient: RECIPIENT,
    amount: amount.toString(),
    fee: fee.toString(),
    txContext: "0200",
    bundle: "00",
    disclosure: [],
    spendAuth: [],
    checksum: "",
  };
}

function prepareResponse(amount: bigint, fee: bigint, remaining: bigint): PrepareResponse {
  return {
    session: `session-${amount}`,
    amount_sompi: Number(amount),
    fee_sompi: Number(fee),
    amount_sompi_exact: amount.toString(),
    fee_sompi_exact: fee.toString(),
    remaining_sompi: Number(remaining),
    remaining_sompi_exact: remaining.toString(),
    bundle_hex: "00",
    disclosure: [],
    spend_auth: [],
    preparedPayment: envelope(amount, fee),
  };
}

/** A fake daemon: each /prepare consumes the next scripted chunk. */
function fakeDaemon(chunks: { amount: bigint; fee: bigint; remaining: bigint }[]) {
  const submitted: string[] = [];
  let next = 0;
  const fetch = (async (url: unknown, init?: { body?: unknown }) => {
    const path = String(url);
    const respond = (body: unknown) => new Response(JSON.stringify(body), { status: 200 });
    if (path.endsWith("/api/wallet/prepare")) {
      const chunk = chunks[next++];
      if (!chunk) return new Response(JSON.stringify({ error: "no more scripted chunks" }), { status: 500 });
      return respond(prepareResponse(chunk.amount, chunk.fee, chunk.remaining));
    }
    if (path.endsWith("/api/wallet/submit")) {
      const body = JSON.parse(String(init?.body)) as { session: string };
      submitted.push(body.session);
      const chunk = chunks[submitted.length - 1]!;
      return respond({
        txid: `tx-${submitted.length}`,
        amount_sompi: Number(chunk.amount),
        fee_sompi: Number(chunk.fee),
        amount_sompi_exact: chunk.amount.toString(),
        fee_sompi_exact: chunk.fee.toString(),
      });
    }
    return new Response(JSON.stringify({ error: `unexpected ${path}` }), { status: 500 });
  }) as typeof globalThis.fetch;
  return { fetch, submitted };
}

function signerStub(log: { maxFees: bigint[] }): PaymentSigner {
  return {
    fullViewingKeyHex: async () => "ff".repeat(96),
    verifyAndSign: async ({ maxFeeSompi }) => {
      log.maxFees.push(maxFeeSompi);
      return [{ index: 0, sig: "aa".repeat(64) }] satisfies DeviceSignature[];
    },
  };
}

function client(fetch: typeof globalThis.fetch): ZKasClient {
  return new ZKasClient({ baseUrl: "http://daemon", network: "mainnet", fetch });
}

test("single-transaction send verifies with the default fee ceiling", async () => {
  const daemon = fakeDaemon([{ amount: 5_000_000_000n, fee: 3_000_000n, remaining: 0n }]);
  const log = { maxFees: [] as bigint[] };
  const result = await client(daemon.fetch).send(signerStub(log), { to: RECIPIENT, amountSompi: 5_000_000_000n });
  assert.equal(result.txids.length, 1);
  assert.equal(result.amountSompi, 5_000_000_000n);
  assert.equal(result.feeSompi, 3_000_000n);
  assert.deepEqual(log.maxFees, [DEFAULT_MAX_FEE_SOMPI]);
});

test("a fragmented wallet pays across chunks until nothing remains", async () => {
  const daemon = fakeDaemon([
    { amount: 6_000_000_000n, fee: 4_400_000n, remaining: 4_000_000_000n },
    { amount: 4_000_000_000n, fee: 3_000_000n, remaining: 0n },
  ]);
  const log = { maxFees: [] as bigint[] };
  const result = await client(daemon.fetch).send(signerStub(log), { to: RECIPIENT, amountSompi: 10_000_000_000n });
  assert.deepEqual(result.txids, ["tx-1", "tx-2"]);
  assert.equal(result.amountSompi, 10_000_000_000n);
  assert.equal(result.feeSompi, 7_400_000n);
  assert.equal(daemon.submitted.length, 2);
});

test("a fee above the approved maximum is refused before signing", async () => {
  // The daemon claims the entire remainder of the wallet as "fee".
  const daemon = fakeDaemon([{ amount: 1_000_000_000n, fee: 42_000_000_000n, remaining: 0n }]);
  const log = { maxFees: [] as bigint[] };
  await assert.rejects(
    client(daemon.fetch).send(signerStub(log), { to: RECIPIENT, amountSompi: 1_000_000_000n }),
    (error: unknown) => error instanceof ZKasSdkError && /above the approved maximum/.test(error.message),
  );
  assert.equal(log.maxFees.length, 0, "the signer must never see an over-fee payment");
  assert.equal(daemon.submitted.length, 0);
});

test("a prover that changes the requested amount is refused", async () => {
  // amount + remaining ≠ requested: the daemon is paying less while claiming completion.
  const daemon = fakeDaemon([{ amount: 900_000_000n, fee: 3_000_000n, remaining: 0n }]);
  await assert.rejects(
    client(daemon.fetch).send(signerStub({ maxFees: [] }), { to: RECIPIENT, amountSompi: 1_000_000_000n }),
    (error: unknown) => error instanceof ZKasSdkError && /changed the requested amount/.test(error.message),
  );
});

test("the ceiling never sits below the caller's own fee floor", () => {
  assert.equal(maxFeeOf({ to: RECIPIENT, amountSompi: 1n }), DEFAULT_MAX_FEE_SOMPI);
  assert.equal(maxFeeOf({ to: RECIPIENT, amountSompi: 1n, feeSompi: 20_000_000n }), 20_000_000n);
  assert.equal(maxFeeOf({ to: RECIPIENT, amountSompi: 1n, maxFeeSompi: 5_000_000n }), 5_000_000n);
});
