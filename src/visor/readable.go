package visor

import (
    "github.com/skycoin/skycoin/src/coin"
    "log"
)

// Encapsulates useful information from the coin.Blockchain
type BlockchainMetadata struct {
    // Most recent block's header
    Head ReadableBlockHeader `json:"head"`
    // Number of unspent outputs in the coin.Blockchain
    Unspents uint64 `json:"unspents"`
    // Number of known unconfirmed txns
    Unconfirmed uint64 `json:"unconfirmed"`
}

func NewBlockchainMetadata(v *Visor) BlockchainMetadata {
    return BlockchainMetadata{
        Head:        NewReadableBlockHeader(&v.blockchain.Head().Header),
        Unspents:    uint64(len(v.blockchain.Unspent.Arr)),
        Unconfirmed: uint64(len(v.UnconfirmedTxns.Txns)),
    }
}

// Wrapper around coin.Transaction, tagged with its status.  This allows us
// to include unconfirmed txns
type Transaction struct {
    Txn    coin.Transaction
    Status TransactionStatus
}

type TransactionStatus struct {
    // This txn is in the unconfirmed pool
    Unconfirmed bool `json:"unconfirmed"`
    // We can't find anything about this txn.  Be aware that the txn may be
    // in someone else's unconfirmed pool, and if valid, it may become a
    // confirmed txn in the future
    Unknown   bool `json:"unknown"`
    Confirmed bool `json:"confirmed"`
    // If confirmed, how many blocks deep in the chain it is. Will be at least
    // 1 if confirmed.
    Height uint64 `json:"height"`
}

func NewUnconfirmedTransactionStatus() TransactionStatus {
    return TransactionStatus{
        Unconfirmed: true,
        Unknown:     false,
        Confirmed:   false,
        Height:      0,
    }
}

func NewUnknownTransactionStatus() TransactionStatus {
    return TransactionStatus{
        Unconfirmed: false,
        Unknown:     true,
        Confirmed:   false,
        Height:      0,
    }
}

func NewConfirmedTransactionStatus(height uint64) TransactionStatus {
    if height == 0 {
        log.Panic("Invalid confirmed transaction height")
    }
    return TransactionStatus{
        Unconfirmed: false,
        Unknown:     true,
        Confirmed:   true,
        Height:      height,
    }
}

type ReadableTransactionHeader struct {
    Hash string   `json:"hash"`
    Sigs []string `json:"sigs"`
}

func NewReadableTransactionHeader(t *coin.TransactionHeader) ReadableTransactionHeader {
    sigs := make([]string, 0, len(t.Sigs))
    for _, s := range t.Sigs {
        sigs = append(sigs, s.Hex())
    }
    return ReadableTransactionHeader{
        Hash: t.Hash.Hex(),
        Sigs: sigs,
    }
}

type ReadableTransactionOutput struct {
    DestinationAddress string `json:"dst"`
    Coins              uint64 `json:"coins"`
    Hours              uint64 `json:"hours"`
}

func NewReadableTransactionOutput(t *coin.TransactionOutput) ReadableTransactionOutput {
    return ReadableTransactionOutput{
        DestinationAddress: t.DestinationAddress.String(),
        Coins:              t.Coins,
        Hours:              t.Hours,
    }
}

type ReadableTransactionInput struct {
    UxOut string `json:"ux_hash"`
}

func NewReadableTransactionInput(t *coin.TransactionInput) ReadableTransactionInput {
    return ReadableTransactionInput{
        UxOut: t.UxOut.Hex(),
    }
}

type ReadableTransaction struct {
    Header ReadableTransactionHeader   `json:"header"`
    In     []ReadableTransactionInput  `json:"inputs"`
    Out    []ReadableTransactionOutput `json:"outputs"`
}

func NewReadableTransaction(t *coin.Transaction) ReadableTransaction {
    in := make([]ReadableTransactionInput, 0, len(t.In))
    for _, i := range t.In {
        in = append(in, NewReadableTransactionInput(&i))
    }
    out := make([]ReadableTransactionOutput, 0, len(t.Out))
    for _, o := range t.Out {
        out = append(out, NewReadableTransactionOutput(&o))
    }
    return ReadableTransaction{
        Header: NewReadableTransactionHeader(&t.Header),
        In:     in,
        Out:    out,
    }
}

type ReadableBlockHeader struct {
    Version  uint32 `json:"version"`
    Time     uint64 `json:"timestamp"`
    BkSeq    uint64 `json:"seq"`
    Fee      uint64 `json:"fee"`
    PrevHash string `json:"prev_hash"`
    BodyHash string `json:"hash"`
}

func NewReadableBlockHeader(b *coin.BlockHeader) ReadableBlockHeader {
    return ReadableBlockHeader{
        Version:  b.Version,
        Time:     b.Time,
        BkSeq:    b.BkSeq,
        Fee:      b.Fee,
        PrevHash: b.PrevHash.Hex(),
        BodyHash: b.BodyHash.Hex(),
    }
}

type ReadableBlockBody struct {
    Transactions []ReadableTransaction `json:"txns"`
}

func NewReadableBlockBody(b *coin.BlockBody) ReadableBlockBody {
    txns := make([]ReadableTransaction, 0, len(b.Transactions))
    for _, txn := range b.Transactions {
        txns = append(txns, NewReadableTransaction(&txn))
    }
    return ReadableBlockBody{
        Transactions: txns,
    }
}

type ReadableBlock struct {
    Header ReadableBlockHeader `json:"header"`
    Body   ReadableBlockBody   `json:"body"`
}

func NewReadableBlock(b *coin.Block) ReadableBlock {
    return ReadableBlock{
        Header: NewReadableBlockHeader(&b.Header),
        Body:   NewReadableBlockBody(&b.Body),
    }
}