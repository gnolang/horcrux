package signer

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestCosignerECIES(t *testing.T) {
	t.Parallel()

	keys := make([]*ecies.PrivateKey, 3)
	pubs := make([]*ecies.PublicKey, 3)

	for i := 0; i < 3; i++ {
		key, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		keys[i] = key
		pubs[i] = &key.PublicKey
	}

	securities := make([]CosignerSecurity, 3)

	for i := 0; i < 3; i++ {
		key := CosignerECIESKey{
			ID:        i + 1,
			ECIESKey:  keys[i],
			ECIESPubs: pubs,
		}
		securities[i] = NewCosignerSecurityECIES(key)

		bz, err := json.Marshal(&key)
		require.NoError(t, err)

		var key2 CosignerECIESKey
		require.NoError(t, json.Unmarshal(bz, &key2))
		require.Equal(t, key, key2)

		require.Equal(t, key.ECIESKey.D.Bytes(), key2.ECIESKey.D.Bytes())

		for i := 0; i < 3; i++ {
			require.Equal(t, key.ECIESPubs[i].X.Bytes(), key2.ECIESPubs[i].X.Bytes())
			require.Equal(t, key.ECIESPubs[i].Y.Bytes(), key2.ECIESPubs[i].Y.Bytes())
		}
	}

	err := testCosignerSecurity(t, securities)
	require.ErrorContains(t, err, "ecies: invalid message")
	require.ErrorContains(t, err, "failed to decrypt")
}

func testCosignerSecurity(t *testing.T, securities []CosignerSecurity) error {
	var (
		mockPub   = []byte("mock_pub")
		mockShare = []byte("mock_share")
	)

	nonce, err := securities[0].EncryptAndSign(2, mockPub, mockShare)
	require.NoError(t, err)

	decryptedPub, decryptedShare, err := securities[1].DecryptAndVerify(1, nonce.PubKey, nonce.Share, nonce.Signature)
	require.NoError(t, err)

	require.Equal(t, mockPub, decryptedPub)
	require.Equal(t, mockShare, decryptedShare)

	_, _, err = securities[2].DecryptAndVerify(1, nonce.PubKey, nonce.Share, nonce.Signature)

	return err
}

func TestConcurrentIterateCosignerECIES(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	keys := make([]*ecies.PrivateKey, 3)
	pubs := make([]*ecies.PublicKey, 3)

	for i := 0; i < 3; i++ {
		key, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		keys[i] = key
		pubs[i] = &key.PublicKey
	}

	securities := make([]CosignerSecurity, 3)

	for i := 0; i < 3; i++ {
		securities[i] = NewCosignerSecurityECIES(CosignerECIESKey{
			ID:        i + 1,
			ECIESKey:  keys[i],
			ECIESPubs: pubs,
		})
	}

	for i := 0; i < 5000; i++ {
		var eg errgroup.Group
		for i, security := range securities {
			security := security
			i := i
			eg.Go(func() error {
				var nestedEg errgroup.Group
				for j, security2 := range securities {
					if i == j {
						continue
					}
					security2 := security2
					j := j
					nestedEg.Go(func() error {
						n, err := security.EncryptAndSign(j+1, []byte("mock_pub"), []byte("mock_share"))
						if err != nil {
							return err
						}

						_, _, err = security2.DecryptAndVerify(i+1, n.PubKey, n.Share, n.Signature)
						if err != nil {
							return err
						}
						return nil
					})
				}
				return nestedEg.Wait()
			})
		}
		require.NoErrorf(t, eg.Wait(), "success count: %d", i)
	}
}

// ---- Fixed-width JSON encoding

// wireCoordinateBytes is the width, in bytes, that the CosignerECIESKey JSON
// encoding gives a secp256k1 coordinate and the private scalar. It deliberately
// restates the width rather than reusing the production constant, so that a
// change to the on-disk format fails these tests.
const wireCoordinateBytes = 32

// eciesScalarSearchLimit bounds the scan for a public point with the coordinate
// widths a test case needs. A given coordinate is short with probability ~1/256,
// so the scan terminates well inside this bound.
const eciesScalarSearchLimit = 100000

type eciesKeyCase struct {
	name string
	key  *ecies.PrivateKey
}

// eciesKeyForScalar derives the secp256k1 ECIES key of a private scalar.
func eciesKeyForScalar(d *big.Int) *ecies.PrivateKey {
	curve := secp256k1.S256()
	x, y := curve.ScalarBaseMult(d.Bytes())

	return &ecies.PrivateKey{
		PublicKey: ecies.PublicKey{
			X:      x,
			Y:      y,
			Curve:  curve,
			Params: ecies.ECIES_AES128_SHA256,
		},
		D: new(big.Int).Set(d),
	}
}

// eciesKeyWithPublicKey returns the key of the smallest scalar whose public key
// satisfies want, scanning scalars in ascending order so the result is stable.
func eciesKeyWithPublicKey(t *testing.T, want func(pub *ecies.PublicKey) bool) *ecies.PrivateKey {
	t.Helper()

	for d := int64(1); d <= eciesScalarSearchLimit; d++ {
		key := eciesKeyForScalar(big.NewInt(d))
		if want(&key.PublicKey) {
			return key
		}
	}

	t.Fatalf("no secp256k1 public key satisfied the case within %d scalars", eciesScalarSearchLimit)

	return nil
}

// eciesKeyCases covers the coordinate and scalar widths the JSON encoding has to
// survive: a coordinate or scalar with leading zero bytes is the case that a
// minimal-length encoding written into a fixed-width window corrupts.
func eciesKeyCases(t *testing.T) []eciesKeyCase {
	t.Helper()

	return []eciesKeyCase{
		{
			name: "full width coordinates",
			key: eciesKeyWithPublicKey(t, func(pub *ecies.PublicKey) bool {
				return len(pub.X.Bytes()) == wireCoordinateBytes && len(pub.Y.Bytes()) == wireCoordinateBytes
			}),
		},
		{
			name: "x has a leading zero byte",
			key: eciesKeyWithPublicKey(t, func(pub *ecies.PublicKey) bool {
				return len(pub.X.Bytes()) < wireCoordinateBytes
			}),
		},
		{
			name: "y has a leading zero byte",
			key: eciesKeyWithPublicKey(t, func(pub *ecies.PublicKey) bool {
				return len(pub.Y.Bytes()) < wireCoordinateBytes
			}),
		},
		{
			name: "private scalar has a leading zero byte",
			key:  eciesKeyForScalar(new(big.Int).Lsh(big.NewInt(1), 247)),
		},
	}
}

// requireECIESKeyRoundTrip asserts that key survives a JSON round trip as the
// same curve point and the same private scalar.
func requireECIESKeyRoundTrip(t *testing.T, key *ecies.PrivateKey) {
	t.Helper()

	original := CosignerECIESKey{
		ID:        1,
		ECIESKey:  key,
		ECIESPubs: []*ecies.PublicKey{&key.PublicKey},
	}

	bz, err := json.Marshal(&original)
	require.NoError(t, err)

	var decoded CosignerECIESKey
	require.NoError(t, json.Unmarshal(bz, &decoded))

	pub := decoded.ECIESPubs[0]

	require.Zerof(t, pub.X.Cmp(key.X),
		"UnmarshalJSON(MarshalJSON(key)).X = %x, want %x", pub.X.Bytes(), key.X.Bytes())
	require.Zerof(t, pub.Y.Cmp(key.Y),
		"UnmarshalJSON(MarshalJSON(key)).Y = %x, want %x", pub.Y.Bytes(), key.Y.Bytes())
	require.Zerof(t, decoded.ECIESKey.D.Cmp(key.D),
		"UnmarshalJSON(MarshalJSON(key)).D = %x, want %x", decoded.ECIESKey.D.Bytes(), key.D.Bytes())
	require.Truef(t, secp256k1.S256().IsOnCurve(pub.X, pub.Y),
		"IsOnCurve(UnmarshalJSON(MarshalJSON(key))) = false, want true")
}

func TestCosignerECIESKeyJSONRoundTrip(t *testing.T) {
	t.Parallel()

	for _, tt := range eciesKeyCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			requireECIESKeyRoundTrip(t, tt.key)
		})
	}
}

func TestCosignerECIESKeyJSONFixedWidth(t *testing.T) {
	t.Parallel()

	for _, tt := range eciesKeyCases(t) {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := CosignerECIESKey{
				ID:        1,
				ECIESKey:  tt.key,
				ECIESPubs: []*ecies.PublicKey{&tt.key.PublicKey},
			}

			bz, err := json.Marshal(&key)
			require.NoError(t, err)

			var wire struct {
				ECIESKey  []byte   `json:"eciesKey"`
				ECIESPubs [][]byte `json:"eciesPubs"`
			}
			require.NoError(t, json.Unmarshal(bz, &wire))

			require.Lenf(t, wire.ECIESKey, wireCoordinateBytes,
				"len(MarshalJSON(key).eciesKey) = %d, want %d", len(wire.ECIESKey), wireCoordinateBytes)
			require.Lenf(t, wire.ECIESPubs[0], 1+2*wireCoordinateBytes,
				"len(MarshalJSON(key).eciesPubs[0]) = %d, want %d", len(wire.ECIESPubs[0]), 1+2*wireCoordinateBytes)
		})
	}
}

func TestCosignerECIESKeyJSONRoundTripGeneratedKeys(t *testing.T) {
	t.Parallel()

	const generatedKeys = 1024

	for i := 0; i < generatedKeys; i++ {
		key, err := ecies.GenerateKey(rand.Reader, secp256k1.S256(), nil)
		require.NoError(t, err)

		requireECIESKeyRoundTrip(t, key)
	}
}
