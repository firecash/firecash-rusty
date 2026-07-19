/** Adapter for the production firecash-signer WASM wrapper. */
export function wasmPaymentSigner(input) {
    return {
        fullViewingKeyHex: () => input.fvkHex(input.seedHex),
        verifyAndSign: ({ network, recipient, amountSompi, maxFeeSompi, prepared }) => input.verifyAndSignPayment(input.seedHex, network, recipient, amountSompi, maxFeeSompi, prepared.bundle_hex, JSON.stringify(prepared.disclosure), JSON.stringify(prepared.spend_auth)),
    };
}
export function assertPaymentRequest(request) {
    if (request.amountSompi <= 0n)
        throw new RangeError("amountSompi must be positive");
    if (request.feeSompi !== undefined && request.feeSompi < 0n)
        throw new RangeError("feeSompi cannot be negative");
    if (request.maxFeeSompi !== undefined && request.maxFeeSompi <= 0n)
        throw new RangeError("maxFeeSompi must be positive");
    if (!request.to.trim())
        throw new TypeError("recipient is required");
}
