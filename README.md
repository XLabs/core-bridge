git clone, then run via `make test` to observe gas costs in forge test traces:

gas costs of `parseAndVerifyVM` (not including transaction overhead):
```
134,689 original
134,689 thirteen sigs (matches as expected)
108,341 using CoreBridgeLib from Solidity SDK (parses and verifies VAA itself after fetching guardian set from core bridge)
 27,677 single signature
 88,686 guardian set from calldata (gscd) optimizations (does not agree with 83k number in the monorepo PR despite additional optimizations)
 69,570 optimized, backwards compatible implementation
 13,874 threshold signature (i.e. single address) optimized version (proxied)
  8,962 threshold signature (i.e. single address) optimized version (no proxy, i.e. unupgradeable)
```

Original gas costs also match gas used field of Action[3] in [Etherscan Parity trace of the sample transaction](https://etherscan.io/vmtrace?txhash=0xedd3ac96bc37961cce21a33fd50449dba257737c168006b40aa65496aaf92449&type=parity).

[guardian set from calldata monorepo PR](https://github.com/wormhole-foundation/wormhole/pull/3366) that passes the guardian set as calldata and only checks the hash - its README is the source of the 83k number above
