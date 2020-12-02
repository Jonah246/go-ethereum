package teller

import (
	"github.com/ethereum/go-ethereum/common"
)

type Teller struct {
	core *tellerCore
}

func NewTeller() *Teller {
	return &Teller{
		core: newTellerCore(),
	}
}

type TellerLog struct {
	TxHash      common.Hash
	Origin      common.Address
	Caller      common.Address
	Callee      common.Address
	Input       string
	BlockNumber int64
}

func (t *Teller) Stop() {
	t.core.stop()
}

func (t *Teller) AppendLog(log TellerLog) {
	t.core.appendLog(log)
}

func (t *Teller) CheckAndMutate(res []byte, caller common.Address, callee common.Address, input []byte, txHash common.Hash, txOrigin common.Address, blockNumber int64) []byte {
	return res
}

func (t *Teller) CheckAndLog(caller common.Address, callee common.Address, input []byte, txHash common.Hash, txOrigin common.Address, blockNumber int64) {
	t.core.checkAndLog(caller, callee, input, txHash, txOrigin, blockNumber)
}
