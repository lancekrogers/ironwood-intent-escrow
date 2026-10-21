# ironwood-intent-escrow

A 2-of-3 FROST escrow on Zcash Ironwood. A fill on another chain spends the
note to the solver. An expiry spends it back to a fresh shielded address.
That address is never an input to the quote, and it is never written on the
other chain.

The plan of record is the festival `ironwood-intent-escrow` in the
Obey-Agent-Economy campaign. The design notes are
`workflow/design/ironwood-intent-escrow`.

This repository does not hold a token, a spending key, or a solver inventory.
