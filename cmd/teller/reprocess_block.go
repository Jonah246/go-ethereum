package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/ethdb"
)

const chainDataPath = "/home/bft/.ethereum/geth"

var once sync.Once
var globalDB *ethdb.Database

// OpenDatabaseWithFreezer opens an existing database with the given name (or
// creates one if no previous can be found) from within the node's data directory,
// also attaching a chain freezer to it that moves ancient chain data from the
// database to immutable append-only files. If the node is an ephemeral one, a
// memory database is returned.
func openDatabaseWithFreezer(name string, cache, handles int, freezer, namespace string) *ethdb.Database {

	once.Do(func() {
		var db ethdb.Database
		var err error
		freezer = filepath.Join(chainDataPath, "ancient")

		db, err = rawdb.NewLevelDBDatabaseWithFreezer(chainDataPath, cache, handles, freezer, namespace)
		if err != nil {
			log.Fatal(err)
		}
		globalDB = &db
	})

	// if err == nil {
	// 	db = n.wrapDatabase(db)
	// }
	return globalDB
}

func testState() error {

	// Assemble the Ethereum object
	chainDb := openDatabaseWithFreezer("chaindata", 1024*8, 10240, "", "eth/db/chaindata/")
	fmt.Println(chainDb)
	block := rawdb.ReadBlock(*chainDb, common.HexToHash("0x7de307abb004b1d4b94e7878a668573cf303110fe6e1fe52ff057d78c60dbe1b"), 11360300)
	fmt.Println(block)
	stateDataBase := state.NewDatabase(*chainDb)
	statedb, err := state.New(
		common.HexToHash("0xc5c99586442dd37a4409880c86c4797686e49bdfd5b70055a68c54df92ad59dc"),
		stateDataBase,
		nil,
	)
	if err != nil {
		return err
	}
	fmt.Println(statedb.GetBalance(common.HexToAddress("0x5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c")))
	return nil
}

func grace() {
	fmt.Println(testState())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(
		signalChan,
		syscall.SIGHUP,  // kill -SIGHUP XXXX
		syscall.SIGINT,  // kill -SIGINT XXXX or Ctrl+c
		syscall.SIGQUIT, // kill -SIGQUIT XXXX
	)

	<-signalChan
	log.Print("os.Interrupt - shutting down...\n")

	// terminate after second signal before callback is done
	go func() {
		<-signalChan
		log.Fatal("os.Kill - terminating...\n")
	}()

	// PERFORM GRACEFUL SHUTDOWN HERE
	if globalDB != nil {
		(*globalDB).Close()
	}
	os.Exit(0)
}
