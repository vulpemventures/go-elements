# go-elements
Go support for Elements transactions 


**The package is currently being developed. DO NOT USE IT**


## 🛣 Roadmap

- [x] Chain parameters (prefix of wif, address, …)
- [ ] CGO bindings for blech32
- [ ] CGO bindings for secp256k1-zkp
- [ ] Tx serialization / deserialization
  - [ ] Use of confidential values instead of pure numbers
  - [ ] Fix order of witness in transaction serialization
  - [ ] Add confidential fields
  - [ ] Serialization for (witness) signature
- [ ] PSET / Bip174 for Elements
- [ ] Blinding outs/ Unblinding ins
- [ ] Slip77
- [ ] Signing a confidential input (use 0 value amounts to produce the hash for the signature)