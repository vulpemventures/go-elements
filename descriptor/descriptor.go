package descriptor

// Wallet is interface to be implemented by various descriptor wallets
type Wallet interface {
	// Type returns type of descriptor wallet (e.g. wpkh, wsh etc.)
	Type() string
	// IsRange returns true if wallet description is of type range which means
	//that key expression provides master key and requires more scripts to be generated
	IsRange() bool
	// Script generates new script, or range of scripts depending on wallet description
	//it returns ScriptResponse which holds script and its derivation path in case wallet descriptor is range
	//if it isn't derivation path will be nil
	//wits ScriptOpts pkg user can specify how many scripts should be generated in case of
	//range wallet descriptor, it also can specify exact index
	Script(opts *ScriptOpts) ([]ScriptResponse, error)
}

// ScriptResponse defines response for Script func
type ScriptResponse struct {
	DerivationPath []uint32
	Script         []byte
}

// ScriptOpts defines options for range type of descriptor wallet
type ScriptOpts struct {
	index        *uint32
	numOfScripts *int
}

// WithIndex defines exact child index for which script should be generated for
//range wallet descriptor
func WithIndex(index uint32) *ScriptOpts {
	return &ScriptOpts{
		index: &index,
	}
}

// WithRange defines how many scripts should be generated for range wallet descriptor
func WithRange(numOfScrips int) *ScriptOpts {
	return &ScriptOpts{
		numOfScripts: &numOfScrips,
	}
}
