package main

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/teller"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/node"
)

// const blockNum = 11331495

// func createContract() {

// }

// func createStateTransition(tx *types.Transaction, tracer vm.Tracer, statedb *state.StateDB) (*core.StateTransition, error) {

// 	signer := types.MakeSigner(params.MainnetChainConfig, new(big.Int).SetUint64(uint64(blockNum)))
// 	origin, _ := signer.Sender(tx)

// 	context := vm.Context{
// 		CanTransfer: core.CanTransfer,
// 		Transfer:    core.Transfer,
// 		Origin:      origin,
// 		Coinbase:    common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
// 		BlockNumber: new(big.Int).SetUint64(uint64(blockNum)),
// 		Time:        new(big.Int).SetUint64(uint64(100)),
// 		Difficulty:  (*big.Int)(big.NewInt(10000)),
// 		GasLimit:    uint64(10000000),
// 		GasPrice:    tx.GasPrice(),
// 	}
// 	msg, err := tx.AsMessage(signer)
// 	if err != nil {
// 		fmt.Println("cannot sign", err)
// 		return nil, err
// 	}

// 	evm := vm.NewEVM(context, statedb, params.MainnetChainConfig, vm.Config{Debug: true, Tracer: tracer})

// 	st := core.NewStateTransition(evm, msg, new(core.GasPool).AddGas(tx.Gas()))

// 	return st, nil
// }

// // func printCall(call callTrace, depth int) {
// // 	for i := 0; i < depth; i++ {
// // 		fmt.Printf("--- ")
// // 	}
// // 	fmt.Printf("Type: %s, From: %s, To: %s PC: %v depth: %v\n",
// // 		call.Type, call.From.Hex(), call.To.Hex(), call.Pc, depth)
// // 	for _, v := range call.Calls {
// // 		printCall(v, depth+1)
// // 	}
// // }

// func parseTracerResult(res json.RawMessage) error {
// 	var ret callTrace
// 	if err := json.Unmarshal(res, &ret); err != nil {
// 		return err
// 	}
// 	printCall(ret, 0)
// 	return nil
// }

// func testTracer(tracerCode string, contractCode string) error {
// 	// configure
// 	alloc := core.GenesisAlloc{}
// 	// alloc.BlockNumber = blockNum
// 	_, statedb := tests.MakePreState(rawdb.NewMemoryDatabase(), alloc, false)

// 	// Configure a blockchain with the given prestate
// 	unsignedTx := types.NewContractCreation(0, big.NewInt(0), uint64(8000000), big.NewInt(5), common.FromHex(contractCode))

// 	privateKeyECDSA, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
// 	if err != nil {
// 		return err
// 	}
// 	signer := types.MakeSigner(params.MainnetChainConfig, new(big.Int).SetUint64(uint64(blockNum)))
// 	tx, err := types.SignTx(unsignedTx, signer, privateKeyECDSA)
// 	fmt.Println("chain id", tx.ChainId())

// 	addr, _ := signer.Sender(tx)

// 	statedb.AddBalance(addr, big.NewInt(100000000000000))

// 	tracer, err := tracers.New(tracerCode)
// 	if err != nil {
// 		return err
// 	}
// 	st, err := createStateTransition(tx, tracer, statedb)
// 	if err != nil {
// 		return err
// 	}

// 	exec, err := st.TransitionDb()
// 	if err != nil {
// 		return err
// 	}
// 	if exec.Err != nil {
// 		fmt.Println("exec err", exec.Err)
// 	}

// 	res, err := tracer.GetResult()
// 	if err != nil {
// 		return err
// 	}

// 	if err := parseTracerResult(res); err != nil {
// 		return err
// 	}

// 	tracer, err = tracers.New(tracerCode)
// 	if err != nil {
// 		return err
// 	}
// 	unsignedTx = types.NewTransaction(1, common.HexToAddress("0xBd770416a3345F91E4B34576cb804a576fa48EB1"), big.NewInt(0), uint64(8000000), big.NewInt(4), common.FromHex("0x52fcba12"))
// 	tx, err = types.SignTx(unsignedTx, signer, privateKeyECDSA)

// 	st, err = createStateTransition(tx, tracer, statedb)
// 	if err != nil {
// 		return err
// 	}

// 	exec, err = st.TransitionDb()
// 	if err != nil {
// 		return err
// 	}
// 	if exec.Err != nil {
// 		fmt.Println("exec err", exec.Err)
// 	}

// 	res, err = tracer.GetResult()
// 	if err != nil {
// 		return err
// 	}
// 	return parseTracerResult(res)
// }

type callTrace struct {
	Type    string          `json:"type"`
	From    common.Address  `json:"from"`
	To      common.Address  `json:"to"`
	Input   hexutil.Bytes   `json:"input"`
	Output  hexutil.Bytes   `json:"output"`
	Gas     *hexutil.Uint64 `json:"gas,omitempty"`
	GasUsed *hexutil.Uint64 `json:"gasUsed,omitempty"`
	Value   *hexutil.Big    `json:"value,omitempty"`
	Pc      int             `json:"pc"`
	Error   string          `json:"error,omitempty"`
	Calls   []callTrace     `json:"calls,omitempty"`
	Logs    []string        `json:"logs"`
}

func testTeller() {
	t := teller.NewTeller(false)
	adr := common.HexToAddress("0xbb2b8038a1640196fbe3e38816f3e67cba72d940")
	input := common.FromHex("0x5909c0d5aabbccdd")
	tx := common.HexToHash("0xa6dddac3e6ee2e579301b097d3ebc22cbc0a07e4974dbc8ebf523236a27f2b47")

	for i := 1; i <= 100; i += 1 {
		t.CheckAndLog(adr, adr, input, tx, adr, int64(i))
	}
}

func testABI() {
	ret := common.FromHex("00000000000000000000000000000000000000000000000000111dfe17d416a00000000000000000000000000000000000000000000000e04128cf275d19a250000000000000000000000000000000000000000000000000000000005fcf3b28")
	r, e := teller.DecodeHelper(common.FromHex("0x0902f1ac"), ret)
	fmt.Println(e)
	myMap := r.([]interface{})
	for k, v := range myMap {
		fmt.Println(k, v)
	}
	fmt.Printf("Type :%t", r)

}

func testTraceTx() error {
	n, err := node.New(&node.Config{})
	if err != nil {
		return err
	}
	// Create Ethereum Service
	config := &eth.Config{}
	config.Ethash.PowMode = ethash.ModeFake
	ethservice, err := eth.New(n, config)
	if err != nil {
		return err
	}
	// service, _ := eth.New()
	api := eth.NewPrivateDebugAPI(ethservice)
	timeout := "1m"
	tracer := "callTracer"
	if err != nil {
		return err
	}
	_, err = api.TraceTransaction(
		context.Background(),
		common.HexToHash("0x8bb8dc5c7c830bac85fa48acad2505e9300a91c3ff239c9517d0cae33b595090"),
		&eth.TraceConfig{
			Timeout: &timeout,
			Tracer:  &tracer,
		})
	return err
}

func main() {
	fmt.Println(testTraceTx())
	// for i := 0; i < 200; i++ {
	// 	tell.AppendLog(teller.TellerLog{
	// 		TxHash: common.HexToHash("0xff"),
	// 	})
	// }
	// for _, k := range tell.WatchList {
	// 	fmt.Println(k.Address.Hex())
	// }
	// tracerCode, err := ioutil.ReadFile(os.Args[1])
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// contractCode, err := ioutil.ReadFile(os.Args[2])
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(testTracer(string(tracerCode), string(contractCode)))
}
