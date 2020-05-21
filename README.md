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
- [x] Pay to Witness Script Hash
- [x] Tx serialization / deserialization
  - [x] Use of confidential values instead of pure numbers
  - [x] Fix order of witness in transaction serialization
  - [x] Add confidential fields
  - [x] Serialization for (witness) signature
- [x] [PSET / Bip174 for Elements](https://github.com/vulpemventures/go-elements/tree/master/pset)
- [ ] CGO bindings for blech32
- [ ] CGO bindings for secp256k1-zkp
- [ ] Blinding outs/ Unblinding ins
- [ ] Slip77
- [ ] Signing a confidential input (use 0 value amounts to produce the hash for the signature)

## 🖥 Development

* Clone repository:

```sh
$ git clone https://github.com/vulpemventures/go-elements.git
```

* Enter into the project folder and install dependencies:

```sh
$ cd go-elements
$ go get -t -v ./...
```

* Run tests

> For running tests it is required to have a running [Nigiri](https://github.com/vulpemventures/nigiri) locally, or at least a remote one reachable from the outside.  
To run the tests it is mandatory to export an `API_URL` environment vriable pointing to the url of nigiri-chopsitcks.  

```
$ nigiri start --liquid
$ export API_URL=http://localhost:3001
$ go test ./... -v
```

## 👷‍♂️ Contributors 

* [@tiero](https://github.com/tiero)
* [@altafan](https://github.com/altafan)
* [@sekulicd](https://github.com/sekulicd)

## License [MIT](https://github.com/vulpemventures/go-elements/blob/master/LICENSE)
