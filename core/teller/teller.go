package teller

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

type Teller struct {
	core *tellerCore

	isMutate bool
	isFound  bool
}

// NewTeller returns a teller object that wraps the global shared tellerCore
// isMuate is true the teller would mutate the return data.
func NewTeller(isMutate bool) *Teller {
	return &Teller{
		core:     newTellerCore(),
		isMutate: isMutate,
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

// callTrace is the result of a callTracer run.
type callTrace struct {
	Type    string          `json:"type"`
	From    common.Address  `json:"from"`
	To      common.Address  `json:"to"`
	Input   hexutil.Bytes   `json:"input"`
	Output  hexutil.Bytes   `json:"output"`
	Gas     *hexutil.Uint64 `json:"gas,omitempty"`
	GasUsed *hexutil.Uint64 `json:"gasUsed,omitempty"`
	Value   *hexutil.Big    `json:"value,omitempty"`
	Error   string          `json:"error,omitempty"`
	Calls   []callTrace     `json:"calls,omitempty"`
}

const LogDetailPath = "/home/bft/go-ethereum/tellerDetail"

func (t *Teller) LogDetail(result json.RawMessage, txHash common.Hash) {
	ioutil.WriteFile(fmt.Sprintf("%s/%s", LogDetailPath, txHash.Hex()), result, 0644)
}

func (t *Teller) CheckAndMutate(res []byte, caller common.Address, callee common.Address, input []byte, txHash common.Hash, txOrigin common.Address, blockNumber int64) []byte {
	if t.isMutate {
		return t.core.checkAndMutate(res, caller, callee, input, txHash, txOrigin, blockNumber)
	}
	return res
}

func (t *Teller) IsFound() bool {
	return t.isFound
}

func (t *Teller) IsMutate() bool {
	return t.isMutate
}

func (t *Teller) CheckAndLog(caller common.Address, callee common.Address, input []byte, txHash common.Hash, txOrigin common.Address, blockNumber int64) {
	ret := t.core.checkAndLog(caller, callee, input, txHash, txOrigin, blockNumber)
	if ret {
		// if len(input) > 4 {
		fmt.Printf("found on tx :%s %s\n", txHash.Hex(), hex.EncodeToString(input[:4]))
		// }
		t.isFound = true
	}
}
