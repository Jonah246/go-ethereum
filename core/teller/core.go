package teller

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"gorm.io/gorm"
)

const LogPath = "/home/jonah1005/contract/tellerLog/"

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

var globalTellerCore *tellerCore
var once sync.Once

// core Teller that all tellers share.
type tellerCore struct {
	WatchList []WatchAddress
	Log       []TellerLog
	mu        *sync.Mutex

	db       *gorm.DB
	logIndex int
	logSize  int
}

func newTellerCore() *tellerCore {
	once.Do(func() {
		db, err := getDbConnection()
		if err != nil {
			panic(err)
		}

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
		globalTellerCore = &tellerCore{
			WatchList: pairs,
			mu:        &sync.Mutex{},
			Log:       make([]TellerLog, logSize),
			logSize:   logSize,
			logIndex:  0,
			db:        db,
		}
	})
	return globalTellerCore
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

func (t *tellerCore) DB() *gorm.DB {
	return t.db
}

func (t *tellerCore) stop() {

	if t.logIndex == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.db.Create(t.Log)
	t.Log = make([]TellerLog, t.logSize)
	t.logIndex = 0

	sqlDB, err := t.db.DB()
	if err != nil {
		panic(err)
	}
	if err := sqlDB.Close(); err != nil {
		panic(err)
	}
}

func (t *tellerCore) checkAndLog(
	caller common.Address, callee common.Address, input []byte,
	txHash common.Hash, txOrigin common.Address, blockNumber int64) bool {
	isFound := false
	for _, w := range t.WatchList {
		if w.Match(callee, input) {
			t.appendLog(TellerLog{
				TxHash:      txHash.Hex(),
				Caller:      caller.Hex(),
				Callee:      callee.Hex(),
				Input:       hex.EncodeToString(input),
				Origin:      txOrigin.Hex(),
				BlockNumber: blockNumber,
			})
			isFound = true
		}
	}
	return isFound
}

func (t *tellerCore) appendLog(log TellerLog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.logIndex < t.logSize {
		t.Log[t.logIndex] = log
		t.logIndex++
	} else {
		t.db.Create(t.Log)

		t.Log = make([]TellerLog, t.logSize)
		t.Log[0] = log
		t.logIndex = 1
	}
}

func DecodeHelper(signature []byte, ret []byte) (interface{}, error) {
	abi, err := abi.JSON(strings.NewReader(uniswap_pair_abi))
	if err != nil {
		return nil, err
	}
	method, err := abi.MethodById(signature)
	if err != nil {
		return nil, err
	}
	return abi.Unpack(method.Name, ret)
}

func encodeHelper(signature []byte, args []interface{}) ([]byte, error) {
	abi, err := abi.JSON(strings.NewReader(uniswap_pair_abi))
	if err != nil {
		return nil, err
	}
	method, err := abi.MethodById(signature)
	if err != nil {
		return nil, err
	}
	return abi.Pack(method.Name, args)
}

func (t *tellerCore) insertMutateState(txHash common.Hash, detail MutateDetail) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, l := range t.Log {
		if l.TxHash == txHash.Hex() {
			t.Log[i].MutateDetail = detail
			t.Log[i].Mutated = true
		}
	}
}

func (t *tellerCore) checkAndMutate(res []byte, caller common.Address, callee common.Address, input []byte, txHash common.Hash, txOrigin common.Address, blockNumber int64) (ret []byte, isMutate bool) {
	if len(input) >= 4 {
		if bytes.Compare(input[:4], common.FromHex("0x0902f1ac")) == 0 {
			if ret, err := DecodeHelper(input[:4], res); err == nil {
				args := ret.([]interface{})
				_, ok := args[0].(*big.Int)
				if ok {
					args[0] = args[0].(*big.Int).Mul(args[0].(*big.Int), big.NewInt(11))
					args[0] = args[0].(*big.Int).Div(args[0].(*big.Int), big.NewInt(10))
					if res, err := encodeHelper(input[:4], args); err != nil {
						return res, true
					}
				}

			}
		} else if bytes.Compare(input[:4], common.FromHex("0x5a3d5493")) == 0 {
			if ret, err := DecodeHelper(input[:4], res); err == nil {
				fmt.Printf("Type: %T, %v", ret, ret)
			}
		}
	}
	return res, false
}
