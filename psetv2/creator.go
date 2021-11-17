package psetv2

type Creator struct {
	pset                   *Pset
	globalFallbackLockTime uint32
}

func NewCreator(p *Pset, globalFallbackLockTime uint32) (*Creator, error) {

	return &Creator{
		pset:                   p,
		globalFallbackLockTime: globalFallbackLockTime,
	}, nil
}

func (c *Creator) Create() (*Pset, error) {
	var psetVersion uint32 = 2
	var txVersion uint32 = 2
	var inputCount uint64 = 0
	var outputCount uint64 = 0
	var elementsTxModifiableFlag uint8 = 0 //0000 0000
	var txModifiableFlag uint8 = 3         //0000 0011
	return &Pset{
		Global: &Global{
			txInfo: TxInfo{
				version:          &txVersion,
				fallBackLockTime: &c.globalFallbackLockTime,
				inputCount:       &inputCount,
				outputCount:      &outputCount,
				txModifiable:     &txModifiableFlag,
			},
			version:                  &psetVersion,
			xPub:                     make([]DerivationPathWithXPub, 0),
			scalars:                  make([][]byte, 0),
			elementsTxModifiableFlag: &elementsTxModifiableFlag,
			proprietaryData:          make([]proprietaryData, 0),
			unknowns:                 make([]keyPair, 0),
		},
	}, nil
}
