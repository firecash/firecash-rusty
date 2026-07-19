import { assertPaymentRequest } from "./signer.js";
/**
 * Largest per-transaction fee the SDK authorizes unless the caller sets a
 * higher `maxFeeSompi` (0.1 ZKAS). The worst honest byte-priced fee — a
 * 6-spend standard transaction — is ~0.044 ZKAS.
 */
export const DEFAULT_MAX_FEE_SOMPI = 10000000n;
/**
 * Hard stop on the chunk loop: a standard transaction spends at most 6 notes,
 * so a badly fragmented wallet could otherwise loop for a very long time.
 */
const MAX_CHUNKS = 24;
const SOMPI_PER_ZKAS = 100000000n;
export class ZKasSdkError extends Error {
    status;
    body;
    constructor(message, status, body) {
        super(message);
        this.status = status;
        this.body = body;
        this.name = "ZKasSdkError";
    }
}
export class ZKasClient {
    #baseUrl;
    #walletToken;
    #network;
    #fetch;
    constructor(config) {
        this.#baseUrl = config.baseUrl.replace(/\/+$/, "");
        this.#walletToken = config.walletToken;
        this.#network = config.network;
        this.#fetch = config.fetch ?? globalThis.fetch.bind(globalThis);
    }
    // ---- wallet lifecycle & state -------------------------------------------
    /** Daemon + wallet status. Check `missing_history` before trusting a balance. */
    async status() {
        return this.#request("GET", "/api/status");
    }
    async balance() {
        return this.#request("GET", "/api/wallet/balance");
    }
    /** Chain-derived history (survives seed restores, unlike device-local lists). */
    async history() {
        return this.#request("GET", "/api/wallet/history");
    }
    /**
     * Register a WATCH-ONLY wallet from a 96-byte full viewing key: the daemon
     * can sync and prepare payments but is powerless to authorize them. This is
     * the only registration path the SDK offers — a seed never belongs on a
     * hosted daemon. `birthdayDaa` bounds the initial scan; always pass it for
     * restored wallets so the daemon knows history before it is complete.
     */
    async watch(fvkHex, birthdayDaa = 0) {
        return this.#request("POST", "/api/wallet/watch", { fvk_hex: fvkHex, birthday: birthdayDaa });
    }
    /**
     * Re-derive the wallet from the chain. The daemon REFUSES a rescan that
     * would lose sight of notes the connected node has pruned (HTTP 409); pass
     * `force` only after the user explicitly accepted that loss.
     */
    async rescan(force = false) {
        return this.#request("POST", "/api/wallet/rescan", force ? { force } : {});
    }
    // ---- payments ------------------------------------------------------------
    /**
     * Send a payment, non-custodially: prepare on the daemon, verify and sign on
     * this device, submit. Splits across up to 24 standard transactions when the
     * wallet's notes require it (each chunk is independently verified and
     * signed). The signer bounds every chunk's fee by `maxFeeSompi`.
     */
    async send(signer, request, onStage) {
        assertPaymentRequest(request);
        const fvk = await signer.fullViewingKeyHex();
        const maxFee = maxFeeOf(request);
        const chunking = request.allowChunking !== false;
        const parts = [];
        let sent = 0n;
        let fees = 0n;
        let owed = request.amountSompi;
        let estimated = 1;
        for (let chunk = 0; chunk < MAX_CHUNKS; chunk++) {
            const progress = () => ({
                part: chunk + 1,
                parts: Math.max(estimated, chunk + 1),
                sentSompi: sent,
                totalSompi: request.amountSompi,
            });
            onStage?.("preparing", progress());
            const prepared = await this.prepare(fvk, { ...request, amountSompi: owed }, chunking);
            const amount = BigInt(prepared.amount_sompi_exact);
            const fee = BigInt(prepared.fee_sompi_exact);
            const remaining = BigInt(prepared.remaining_sompi_exact ?? Math.trunc(prepared.remaining_sompi ?? 0));
            if (amount + remaining !== owed) {
                throw new ZKasSdkError("prover changed the requested amount");
            }
            if (amount > 0n && chunk === 0 && remaining > 0n) {
                estimated = Number((request.amountSompi + amount - 1n) / amount);
            }
            // Plain-language refusal before any signing work; the signer would refuse
            // anyway (it reads the real fee from the bundle, not this figure).
            if (fee > maxFee) {
                throw new ZKasSdkError(`prover asked for a fee of ${zkas(fee)} ZKAS, above the approved maximum of ${zkas(maxFee)} ZKAS`);
            }
            onStage?.("verifying", progress());
            onStage?.("signing", progress());
            const signatures = await signer.verifyAndSign({
                network: this.#network,
                recipient: request.to.trim(),
                amountSompi: amount,
                maxFeeSompi: maxFee,
                prepared,
            });
            onStage?.("broadcasting", progress());
            const result = await this.submit(prepared.session, signatures);
            parts.push({ txid: result.txid, amountSompi: BigInt(result.amount_sompi_exact), feeSompi: BigInt(result.fee_sompi_exact) });
            sent += BigInt(result.amount_sompi_exact);
            fees += BigInt(result.fee_sompi_exact);
            if (remaining <= 0n)
                break;
            owed = remaining;
            if (chunk === MAX_CHUNKS - 1) {
                throw new ZKasSdkError(`sent ${zkas(sent)} ZKAS in ${parts.length} transactions, but ${zkas(owed)} ZKAS could not be sent: ` +
                    `the wallet's balance is split across too many small notes. Consolidate and send the rest.`);
            }
        }
        onStage?.("submitted");
        return { txid: parts[0].txid, txids: parts.map((p) => p.txid), parts, amountSompi: sent, feeSompi: fees };
    }
    async prepare(fvkHex, request, allowPartial = false) {
        return this.#request("POST", "/api/wallet/prepare", {
            fvk_hex: fvkHex,
            to: request.to.trim(),
            amount_sompi: request.amountSompi.toString(),
            ...(request.feeSompi === undefined ? {} : { fee: request.feeSompi.toString() }),
            ...(request.memo === undefined ? {} : { memo: request.memo }),
            ...(allowPartial ? { allow_partial: true } : {}),
        });
    }
    async submit(session, signatures) {
        return this.#request("POST", "/api/wallet/submit", { session, sigs: signatures });
    }
    async #request(method, path, body) {
        const headers = new Headers();
        if (body !== undefined)
            headers.set("content-type", "application/json");
        if (this.#walletToken !== undefined)
            headers.set("x-wallet-token", this.#walletToken);
        const response = await this.#fetch(`${this.#baseUrl}${path}`, {
            method,
            headers,
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        const value = await response.json().catch(() => undefined);
        if (!response.ok) {
            const message = typeof value === "object" && value !== null && "error" in value
                ? String(value.error)
                : `wallet service returned ${response.status}`;
            throw new ZKasSdkError(message, response.status, value);
        }
        return value;
    }
}
/** The effective per-transaction fee ceiling of a request: the caller's ceiling
 * or the standing default, never below the caller's own fee floor. */
export function maxFeeOf(request) {
    const base = request.maxFeeSompi ?? DEFAULT_MAX_FEE_SOMPI;
    return request.feeSompi !== undefined && request.feeSompi > base ? request.feeSompi : base;
}
function zkas(sompi) {
    const whole = sompi / SOMPI_PER_ZKAS;
    const frac = (sompi % SOMPI_PER_ZKAS).toString().padStart(8, "0").replace(/0+$/, "");
    return frac ? `${whole}.${frac}` : whole.toString();
}
