package visor

import "github.com/skycoin/skycoin/src/coin"

const (
	// Maximum supply of skycoins
	MaxCoinSupply uint64 = 2e8 // 100,000,000 million

	// Number of distribution addresses
	DistributionAddressesTotal uint64 = 100

	DistributionAddressInitialBalance uint64 = MaxCoinSupply / DistributionAddressesTotal

	// Initial number of unlocked addresses
	InitialUnlockedCount uint64 = 25

	// Number of addresses to unlock per unlock time interval
	UnlockAddressRate uint64 = 5

	// Unlock time interval, measured in seconds
	// Once the InitialUnlockedCount is exhausted,
	// UnlockAddressRate addresses will be unlocked per UnlockTimeInterval
	UnlockTimeInterval uint64 = 60 * 60 * 24 * 365 // 1 year
)

func init() {
	if MaxCoinSupply%DistributionAddressesTotal != 0 {
		panic("MaxCoinSupply should be perfectly divisible by DistributionAddressesTotal")
	}
}

// Returns a copy of the hardcoded distribution addresses array.
// Each address has 1,000,000 coins. There are 100 addresses.
func GetDistributionAddresses() []string {
	addrs := make([]string, len(distributionAddresses))
	for i := range distributionAddresses {
		addrs[i] = distributionAddresses[i]
	}
	return addrs
}

// Returns distribution addresses that are unlocked, i.e. they have spendable outputs
func GetUnlockedDistributionAddresses() []string {
	// The first InitialUnlockedCount (30) addresses are unlocked by default.
	// Subsequent addresses will be unlocked at a rate of UnlockAddressRate (5) per year,
	// after the InitialUnlockedCount (30) addresses have no remaining balance.
	// The unlock timer will be enabled manually once the
	// InitialUnlockedCount (30) addresses are distributed.

	// NOTE: To have automatic unlocking, transaction verification would have
	// to be handled in visor rather than in coin.Transactions.Visor(), because
	// the coin package is agnostic to the state of the blockchain and cannot reference it.
	// Instead of automatic unlocking, we can hardcode the timestamp at which the first 30%
	// is distributed, then compute the unlocked addresses easily here.

	addrs := make([]string, InitialUnlockedCount)
	for i := range distributionAddresses[:InitialUnlockedCount] {
		addrs[i] = distributionAddresses[i]
	}
	return addrs
}

// Returns distribution addresses that are locked, i.e. they have unspendable outputs
func GetLockedDistributionAddresses() []string {
	// TODO -- once we reach 30% distribution, we can hardcode the
	// initial timestamp for releasing more coins
	addrs := make([]string, DistributionAddressesTotal-InitialUnlockedCount)
	for i := range distributionAddresses[InitialUnlockedCount:] {
		addrs[i] = distributionAddresses[InitialUnlockedCount+uint64(i)]
	}
	return addrs
}

// Returns true if the transaction spends locked outputs
func TransactionIsLocked(inUxs coin.UxArray) bool {
	lockedAddrs := GetLockedDistributionAddresses()
	lockedAddrsMap := make(map[string]struct{})
	for _, a := range lockedAddrs {
		lockedAddrsMap[a] = struct{}{}
	}

	for _, o := range inUxs {
		uxAddr := o.Body.Address.String()
		if _, ok := lockedAddrsMap[uxAddr]; ok {
			return true
		}
	}

	return false
}

var distributionAddresses = [DistributionAddressesTotal]string{
	"2JJEtAuBUDBJ8xHNskrxuuC2TktUWHQeNA2",
	"2BjdXGuY7LCj8M1JszCoM8trqWirK9f8ofg",
	"29cfZuRsF7bKu197gL6J5dbaxwf83fubZ5C",
	"39QeiLwUop2nXqV8nZoMY8xFTpCH9iuyHM",
	"qoMoYW2ttAvEHVCkdKMceE8wnAssDT2PPF",
	"u77ohGCZ9w8VErvam5aqCffWU57yFqZb5P",
	"23dMCqQipWVXBGe7Y3fP5Uuup2TtQEKW724",
	"2dYKJ1RAcbFbh34ksm8XmQNnj25fhW4mnTZ",
	"GzUFgj9fqMMxFTREa48DontB7abbqfrBC6",
	"2Mamt9DPQd8s9qsSGqKaNhdpqk4hoMpj6Jo",
	"2MXQBaa2pfM3p1c6FXsvx55CHtDR2sA7mUT",
	"L9C9wAij4nGKi4iShKqF6PyfRRHU1JSC2U",
	"2kNnuhJHJsVSD6xWg44kSiMFNfNpqnGHXUx",
	"NGJ2SGW5SgEXGoD5Y43y7Mppg5sN3SN52F",
	"2S6TBN54SoTWNbcPpcvUikUJh2Jd7U9pMLB",
	"3cMne2y7dn26DdBjwvWjtgMJXVNkeMh9kZ",
	"2SVq67bySStCz8pNqUgyHR9aeDpwPxKpjP6",
	"24FjwvFss4Dm1Cq8z4NjycBJns6pAL3rV4S",
	"aggUFSVUkPQ15gb8XPWvrjTsCVeW1hBaG2",
	"2Sfm5yduWFTgaCAkLnJW6HUj5ndB6dVHTJL",
	"2hr8vxn3bW28HpKFedbu38F3YYmm9oXjwHb",
	"2ejik8FyBcmKSKYugz2CNP4GNoLCnzJGSyg",
	"PnrmTEoVPJpJ4GcTjoF8Bw7GWsxdRS9gTa",
	"2X4eHhgJxTWGVKJM4NRoZRprfBap8EDczs2",
	"27SLH5Ne8iiqkjYD3jnLufAG6sZkyWMSN5p",
	"WhAnCQiHh3HheBrQiaSpgaYmtvsmB1y7VP",
	"2iEH4D9wwEpZ62FwyufTKMYmC24s2E9eXNE",
	"2jR5LH5gPKY9T2Bdg3yyyfMonp2YNddgZ52",
	"2kbwLr6YBCPqRUBQNTnVKd9xVLyp1UAEHwv",
	"2aNq6bh1yrRVDobqjyacHCdurwuRqYp5Eut",
	"2Gz9DUUkZUqWZSixvtGKJi8sQkUCh47QayW",
	"3dmvZTAAf3XhYGPwuxuXoZPhukt4gC7XsP",
	"hhSqLT9jerGJQWvHmvXf8HopWcxL4gXMCv",
	"Uy14Zesirps9cwaBnepWEXmWEu79fCc8kx",
	"BBcDkrCt5TLKUvCHwok61T7v3zkVYoTLSx",
	"JJuhZsE5urn7WduHFgf5g8XwvCXfxCrfvV",
	"23sT4AChLHL9kadCFDEG7Lj36pTf3XjLoUm",
	"nAKC8FqwUdj4PKmk3ZFAwGFq2RrkVwvaCH",
	"EJg6wRVoL1hyxTNtttVkhedivAvw1gajHv",
	"cUURiFKpE3qnnoYar3PiTKA2wU9FWofs5U",
	"M6TWCmeJ6sqb6qHiciAofJ7z6m1ZrpwAVX",
	"28JU41aT12JXcb7kHbKBeqbWPfdVq5zAJCV",
	"Aas1kBHPvVmrpXfCJsnvf4fTRi35zFQK6h",
	"y2wcV6vtZCHhjwRddZFbjj2Gmutfs3mWqa",
	"qH17kDsF5qgQBmufygFiup13XN18P6XxCK",
	"2moGwJZkeidsEkWyMevfVc2j8EGQrwheNYt",
	"CvScP6DZYka6Qn7SGRzRhtZZwut1gBZLn1",
	"qSqeLxDRBRd9eFxje5GsHoEvSHdWfkxGtS",
	"2XRHq1BFqDqPKxxup5NGGTbdakD5WYg6rB7",
	"LMXuKJnM86z7guE76e13RMNA9xxRjzcRVQ",
	"FLfwWKmXcXSwLBcL5pub38W8hszUp1UkYP",
	"29dXgiEBqk9jmjjbjWG3veiaGUhe4x4Kxxp",
	"2CGahZJoQWXACD8rVhiAmBqdsia73y3Tt6H",
	"2DjjqCQ9FiXGVNxvn9H3UrVMmTt9qdjExgF",
	"Vc8E6H3dvEgW6fxSwS8dqy7fSyBWieYYkk",
	"2JhRUXYhWBmpJnXtRZbBfMH5fQAKUGkcWuX",
	"yFs1ptqRNDBtEysEC2q2Rs6Y7VoVazevFc",
	"25pLSp1k2ffuYzFkK2vTkV7nsaKPZgsEkcJ",
	"2anhiQddMQ92KKhpNsuxwmdDLd77v7HuMJ",
	"pgd4VkE7xVTWC89A5EemfhbKg23vbomzYB",
	"2iyv3X68Eg33Zbe8AWmv6SBD6F3UgUFw8Pd",
	"sURLj4pe8Doee1Ghms6DEUgmhbuU4KqbBQ",
	"2UoRpd8XqGikyhnRcrV8bhLrn8zbwyQ4cSo",
	"uxhd6fsYBf97otqCEdViVx9AtFLUsTpDbF",
	"e98bRm4Sc7CPSxePwUh9PWqcM64EnXhoKG",
	"2KmWJsD5sNLFaPFHKn4q2SCNQKU8NsFpK1B",
	"TXyS1X3izM8DqYVd61kTVN3LF9HHJcjdAB",
	"DUAXxT4GzZcm7u94w3oNoE3gRyjaMVxkEW",
	"cfAMxg18RBgg7XkoP6kPGhgiiQLEzqct7o",
	"2GsxADgubEXTzieoRkHN3Zq4Uq2Z9DjPgfo",
	"AULy9rP5ySLHCBPDnqu3e1LEa77kCGLEXb",
	"pBunuc34YERVaeY8H4DjpnFnDviQvTtoCP",
	"5VieYZQ245sC7iLRGcsJdajmmG7jc4Y4hd",
	"2abiLVQyM3VaH8Wc3vXs9dAYYkJbRMnz9hL",
	"2BnkGrPo1DGhH9Rp42dHg3BKM2nc29McmXu",
	"2LCUJZMDCnBVyiRBmu64AVhJ8VsJXpHes1k",
	"HGp8mbubmcjoS9xP9TfG43niYht1XkstFn",
	"Jnxrp3fK6kG6oTAcBhTg2Tp7PkzpBveRCo",
	"3GZdt8po1j6LgNMHJdekZcLZzi2RpKjmYZ",
	"JvVWrxH2nRcYagH2LApX8cj1dbaED5dozG",
	"RGcEWu9ryJ5MmsrTFZv7ZU551hKoviAGMf",
	"2YsTfoBUxEuPzWqrpM7VExouSUvEURH1oNv",
	"28Wzos2Ya1JH94T6agVEwKTfQKh8oEcufi4",
	"crkqc88qyYUhvYAyAbVVLTMdTHEKNcemR1",
	"2Qc2JTPbnFP1vfHw1uExcMMok1DwwgK64aa",
	"nVuNAbDzRLwtD4mmNLZcjreF2RHUzYNKLr",
	"Gt8JEfdvxnbh8ChMcjazBwdUckMgigoPLn",
	"2YDnqqAuiF9Nw1JHsdVhx2SzqBc5Upgodfu",
	"2MB7aQ3PJ3YySHbRNFFtiYESpuXkuJ2rzfj",
	"cYW3NpmSQcF91jHsBpphMsPEJRiT25iqVC",
	"Kkpd9AXAtNHLsq6Xa6gw5Ha2Q8RfedLRvN",
	"nYEdPuNCeGeyWxJzcp2grBFTSV891nBigk",
	"9yifSbf2zemFmUQVBgDWaxu8wSYVrBSpSc",
	"2Frw2Je3LwUs8RkCtCprrAXKJBeCFX5fkqm",
	"2UN4vzSgKUvUteWrx6MerJAfLRy6SCQ9ZyL",
	"2BSVbLKLPEPK7arnnFmiQSMTBTNfPSnpNqC",
	"5kF14Mh8BpkRR3mu8tdwKJxnyy5JPjR3WP",
	"vCFsyTQ3bNKafqrMnaJmDVq8tnU56QdAsa",
	"eH6X9wrNeyfy5HEjE2NmKwfaefBF35JWss",
	"9NGErBjwDmBa6UTBbVEGKJ5TSQ8MU3Hr18",
}
