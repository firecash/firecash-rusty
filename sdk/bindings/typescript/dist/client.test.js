import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_MAX_FEE_SOMPI, ZKasClient, ZKasSdkError, maxFeeOf } from "./client.js";
const RECIPIENT = "zkas:qqtestrecipient";
function envelope(amount, fee) {
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
function prepareResponse(amount, fee, remaining) {
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
function fakeDaemon(chunks) {
    const submitted = [];
    let next = 0;
    const fetch = (async (url, init) => {
        const path = String(url);
        const respond = (body) => new Response(JSON.stringify(body), { status: 200 });
        if (path.endsWith("/api/wallet/prepare")) {
            const chunk = chunks[next++];
            if (!chunk)
                return new Response(JSON.stringify({ error: "no more scripted chunks" }), { status: 500 });
            return respond(prepareResponse(chunk.amount, chunk.fee, chunk.remaining));
        }
        if (path.endsWith("/api/wallet/submit")) {
            const body = JSON.parse(String(init?.body));
            submitted.push(body.session);
            const chunk = chunks[submitted.length - 1];
            return respond({
                txid: `tx-${submitted.length}`,
                amount_sompi: Number(chunk.amount),
                fee_sompi: Number(chunk.fee),
                amount_sompi_exact: chunk.amount.toString(),
                fee_sompi_exact: chunk.fee.toString(),
            });
        }
        return new Response(JSON.stringify({ error: `unexpected ${path}` }), { status: 500 });
    });
    return { fetch, submitted };
}
function signerStub(log) {
    return {
        fullViewingKeyHex: async () => "ff".repeat(96),
        verifyAndSign: async ({ maxFeeSompi }) => {
            log.maxFees.push(maxFeeSompi);
            return [{ index: 0, sig: "aa".repeat(64) }];
        },
    };
}
function client(fetch) {
    return new ZKasClient({ baseUrl: "http://daemon", network: "mainnet", fetch });
}
test("single-transaction send verifies with the default fee ceiling", async () => {
    const daemon = fakeDaemon([{ amount: 5000000000n, fee: 3000000n, remaining: 0n }]);
    const log = { maxFees: [] };
    const result = await client(daemon.fetch).send(signerStub(log), { to: RECIPIENT, amountSompi: 5000000000n });
    assert.equal(result.txids.length, 1);
    assert.equal(result.amountSompi, 5000000000n);
    assert.equal(result.feeSompi, 3000000n);
    assert.deepEqual(log.maxFees, [DEFAULT_MAX_FEE_SOMPI]);
});
test("a fragmented wallet pays across chunks until nothing remains", async () => {
    const daemon = fakeDaemon([
        { amount: 6000000000n, fee: 4400000n, remaining: 4000000000n },
        { amount: 4000000000n, fee: 3000000n, remaining: 0n },
    ]);
    const log = { maxFees: [] };
    const result = await client(daemon.fetch).send(signerStub(log), { to: RECIPIENT, amountSompi: 10000000000n });
    assert.deepEqual(result.txids, ["tx-1", "tx-2"]);
    assert.equal(result.amountSompi, 10000000000n);
    assert.equal(result.feeSompi, 7400000n);
    assert.equal(daemon.submitted.length, 2);
});
test("a fee above the approved maximum is refused before signing", async () => {
    // The daemon claims the entire remainder of the wallet as "fee".
    const daemon = fakeDaemon([{ amount: 1000000000n, fee: 42000000000n, remaining: 0n }]);
    const log = { maxFees: [] };
    await assert.rejects(client(daemon.fetch).send(signerStub(log), { to: RECIPIENT, amountSompi: 1000000000n }), (error) => error instanceof ZKasSdkError && /above the approved maximum/.test(error.message));
    assert.equal(log.maxFees.length, 0, "the signer must never see an over-fee payment");
    assert.equal(daemon.submitted.length, 0);
});
test("a prover that changes the requested amount is refused", async () => {
    // amount + remaining ≠ requested: the daemon is paying less while claiming completion.
    const daemon = fakeDaemon([{ amount: 900000000n, fee: 3000000n, remaining: 0n }]);
    await assert.rejects(client(daemon.fetch).send(signerStub({ maxFees: [] }), { to: RECIPIENT, amountSompi: 1000000000n }), (error) => error instanceof ZKasSdkError && /changed the requested amount/.test(error.message));
});
test("the ceiling never sits below the caller's own fee floor", () => {
    assert.equal(maxFeeOf({ to: RECIPIENT, amountSompi: 1n }), DEFAULT_MAX_FEE_SOMPI);
    assert.equal(maxFeeOf({ to: RECIPIENT, amountSompi: 1n, feeSompi: 20000000n }), 20000000n);
    assert.equal(maxFeeOf({ to: RECIPIENT, amountSompi: 1n, maxFeeSompi: 5000000n }), 5000000n);
});
