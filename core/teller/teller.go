package teller

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

var globalTeller *Teller
var once sync.Once

func NewTeller() *Teller {
	once.Do(func() {
		logSize := 100
		data := struct {
			Data UniswapData `jons:"data"`
		}{}
		json.Unmarshal([]byte(uniswapParisJSON), &data)
		pairs := make([]WatchAddress, len(data.Data.Pairs)*4)

		// 0902f1ac  =>  getReserves()
		// 5909c0d5  =>  price0CumulativeLast()
		// 5a3d5493  =>  price1CumulativeLast()
		// 7464fc3d  =>  kLast()
		for i, pair := range data.Data.Pairs {
			pairs[i*4] = WatchAddress{
				Address: common.HexToAddress(pair.ID),
				// getReserves()
				Signature: common.FromHex("0x0902f1ac"),
			}
			pairs[i*4+1] = WatchAddress{
				Address: common.HexToAddress(pair.ID),
				// price0CumulativeLast()
				Signature: common.FromHex("0x5909c0d5"),
			}
			pairs[i*4+2] = WatchAddress{
				Address: common.HexToAddress(pair.ID),
				// price1CumulativeLast()
				Signature: common.FromHex("0x5a3d5493"),
			}
			pairs[i*4+3] = WatchAddress{
				Address: common.HexToAddress(pair.ID),
				// kLast()
				Signature: common.FromHex("0x7464fc3d"),
			}
		}
		globalTeller = &Teller{
			WatchList: pairs,
			mu:        &sync.Mutex{},
			Log:       make([]TellerLog, logSize),
			logSize:   logSize,
			logIndex:  0,
		}
	})
	return globalTeller
}

const LogPath = "/home/bft/go-ethereum/tellerLog/"

type WatchAddress struct {
	Address   common.Address
	Signature []byte
}

type UniswapData struct {
	Pairs []UniswapPair `jons:"pairs"`
}

type UniswapPair struct {
	ID string `json:"id"`
}

func (w WatchAddress) Match(address common.Address, input []byte) bool {
	if address.Hex() != w.Address.Hex() {
		return false
	}
	if len(w.Signature) == 0 {
		return true
	}
	if len(w.Signature) > len(input) {
		return false
	}
	return bytes.Compare(w.Signature, input[:len(w.Signature)]) == 0
}

type Teller struct {
	WatchList []WatchAddress
	Log       []TellerLog
	mu        *sync.Mutex

	logIndex int
	logSize  int
}

type TellerLog struct {
	TxHash      common.Hash
	Caller      common.Address
	Callee      common.Address
	Input       string
	BlockNumber int64
}

var deFaultAddress = [...]string{}

func (t *Teller) WriteToFile() {
}

func (t *Teller) AppendLog(log TellerLog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.logIndex < t.logSize {
		t.Log[t.logIndex] = log
		t.logIndex += 1
		fmt.Println("current log size", t.logIndex)
	} else {
		filePath := fmt.Sprintf("%s%v.json", LogPath, t.Log[0].BlockNumber)
		b, err := json.MarshalIndent(t.Log, "", "")
		if err != nil {
			fmt.Println("Err:", err)
			return
		}
		ioutil.WriteFile(filePath, b, 0644)
		fmt.Printf("write %v logs into %s\n", t.logSize, filePath)
		// t.WriteToFile()
		t.Log = make([]TellerLog, t.logSize)
		t.Log[0] = log
		t.logIndex = 1
	}
}

func (t *Teller) CheckAndLog(caller common.Address, callee common.Address, input []byte, txHash common.Hash, blockNumber int64) {
	for _, w := range t.WatchList {
		if w.Match(callee, input) {
			fmt.Printf("found one match. tx: %s\n", txHash.Hex())
			t.AppendLog(TellerLog{
				TxHash:      txHash,
				Caller:      caller,
				Callee:      callee,
				Input:       hex.EncodeToString(input),
				BlockNumber: blockNumber,
			})
		}
	}
}
