## Pitch

Cross-chain intents have a privacy problem. When you swap shielded Zcash through an intent today, a refund address is written to the other chain the moment your deposit registers, whether or not a refund ever happens.

This escrow never writes a Zcash address, a Zcash transaction ID, or a Zcash amount on the other chain.

The payer locks one shielded note in Zcash's Ironwood pool. Three FROST shares control it: the payer's, the solver's, and a deadline device that belongs to the payer. Any two can spend. If the solver pays on Near, the note goes to the solver. If not, it goes back to a fresh shielded address after the quote expires.

## Tests

The test suite runs offline. It proves that one share alone cannot produce a signature. It proves that the checker rejects a transparent output and an all-zero outgoing viewing key, and that the receipt check rejects a Near payment with a Zcash address planted in it. And it proves the new refund check: when a quote's claimed Near payment checks out, neither refund signer will sign.

## Verify

A judge needs no keys and no funds. This run is live. The verify command reads the recorded runs in the repository. It fetches all four Zcash transactions from a public light server, and checks that each matches its recorded bytes and block height and passes the Zcash checker. It fetches the solver's payment from Near's archival node, and checks that it pays the quote and carries no Zcash value. Pass on every line means the records are what the two chains hold.

## Fill

This is the recorded fill run, not a live one. The payer funded the escrow in a transaction mined at block four million, five hundred thirty thousand, five hundred fifty-nine. The solver paid the quote on Near testnet, and the decoded call shows that only the quote ID rides in the memo. The payer fetched that payment again from an archival node and checked it. The deadline device was handed the release first, and refused it. Then the payer's share and the solver's share signed it.

## Refund

This is the log of the real refund run, replayed, not a live one. First, the refund check fetched the fill quote's payment from Near, and refused to refund that quote, because it was paid. Then the payer funded a second escrow, whose quote had already expired. The deadline device found no fill claim for it, and signed. The note went to a fresh address from the payer's refund key, an address that appears in no quote and nowhere on Near. This is testnet only. The key came from a trusted dealer, and the deadline device is the payer's own.
