<div align="center">
	<img width="256" src="go-elements-gopher.png">
</div>

# go-elements

[![Build Status](https://travis-ci.com/vulpemventures/go-elements.svg?branch=master)](https://travis-ci.com/vulpemventures/go-elements)
[![Bitcoin Donate](https://badgen.net/badge/Bitcoin/Donate/F7931A?icon=bitcoin)](https://blockstream.info/address/3MdERN32qiMnQ68bSSee5CXQkrSGx1iStr)



Go support for confidential transactions on Elements-based blockchains 


**The package is currently being developed. DO NOT USE IT**


## 🛣 Roadmap

- [x] Chain parameters (prefixes, magic numbers, …)
- [x] Pay to Public Key Hash
- [x] Pay to Script Hash
- [x] Pay to Witness Public Key Hash
- [ ] Pay to Witness Script Hash
- [x] Tx serialization / deserialization
  - [ ] Use of confidential values instead of pure numbers
  - [x] Fix order of witness in transaction serialization
  - [ ] Add confidential fields
  - [x] Serialization for (witness) signature
- [x] [PSET / Bip174 for Elements](https://github.com/vulpemventures/go-elements/tree/master/pset)
- [ ] CGO bindings for blech32
- [ ] CGO bindings for secp256k1-zkp
- [ ] Blinding outs/ Unblinding ins
- [ ] Slip77
- [ ] Signing a confidential input (use 0 value amounts to produce the hash for the signature)
