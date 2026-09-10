package signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	cometjson "github.com/cometbft/cometbft/libs/json"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/sync/errgroup"
)

var _ CosignerSecurity = &CosignerSecurityECIES{}

// CosignerSecurityECIES is an implementation of CosignerSecurity
// using ECIES for encryption and ECDSA for digital signature.
type CosignerSecurityECIES struct {
	key          CosignerECIESKey
	eciesPubKeys map[int]CosignerECIESPubKey
}

// CosignerECIESKey is a cosigner's ECIES public key.
type CosignerECIESPubKey struct {
	ID        int
	PublicKey *ecies.PublicKey
}

const (
	// eciesCoordinateBytes is the width of a secp256k1 field element in the
	// CosignerECIESKey JSON encoding. Coordinates and the private scalar are
	// zero padded on the left to this width: the decoder reads fixed windows,
	// so a minimal-length value would be recovered as a different number.
	eciesCoordinateBytes = 32

	// eciesPubKeyBytes is the width of an uncompressed secp256k1 public key in
	// the CosignerECIESKey JSON encoding: a 0x04 prefix followed by the X and Y
	// coordinates.
	eciesPubKeyBytes = 1 + 2*eciesCoordinateBytes

	// eciesPubKeyPrefix marks a public key as an uncompressed point.
	eciesPubKeyPrefix = 0x04
)

// CosignerECIESKey is an ECIES key for an m-of-n threshold signer, composed of a private key and n public keys.
type CosignerECIESKey struct {
	ECIESKey  *ecies.PrivateKey  `json:"eciesKey"`
	ID        int                `json:"id"`
	ECIESPubs []*ecies.PublicKey `json:"eciesPubs"`
}

func (key *CosignerECIESKey) MarshalJSON() ([]byte, error) {
	type Alias CosignerECIESKey

	// marshal our private key and all public keys as fixed-width big-endian
	privateBytes := key.ECIESKey.D.FillBytes(make([]byte, eciesCoordinateBytes))
	pubKeysBytes := make([][]byte, len(key.ECIESPubs))
	for i, pubKey := range key.ECIESPubs {
		pubBz := make([]byte, eciesPubKeyBytes)
		pubBz[0] = eciesPubKeyPrefix
		pubKey.X.FillBytes(pubBz[1 : 1+eciesCoordinateBytes])
		pubKey.Y.FillBytes(pubBz[1+eciesCoordinateBytes:])
		pubKeysBytes[i] = pubBz
	}

	return json.Marshal(&struct {
		ECIESKey  []byte   `json:"eciesKey"`
		ECIESPubs [][]byte `json:"eciesPubs"`
		*Alias
	}{
		ECIESKey:  privateBytes,
		ECIESPubs: pubKeysBytes,
		Alias:     (*Alias)(key),
	})
}

func (key *CosignerECIESKey) UnmarshalJSON(data []byte) error {
	type Alias CosignerECIESKey

	aux := &struct {
		ECIESKey  []byte   `json:"eciesKey"`
		ECIESPubs [][]byte `json:"eciesPubs"`
		*Alias
	}{
		Alias: (*Alias)(key),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// unmarshal the public key bytes for each cosigner, rejecting anything the
	// fixed-width encoding cannot have produced
	curve := secp256k1.S256()
	key.ECIESPubs = make([]*ecies.PublicKey, len(aux.ECIESPubs))
	for i, pubBz := range aux.ECIESPubs {
		if len(pubBz) != eciesPubKeyBytes {
			return fmt.Errorf("ecies pub key %d: got %d bytes, want %d", i+1, len(pubBz), eciesPubKeyBytes)
		}

		if pubBz[0] != eciesPubKeyPrefix {
			return fmt.Errorf("ecies pub key %d: got prefix 0x%02x, want 0x%02x",
				i+1, pubBz[0], eciesPubKeyPrefix)
		}

		pub := &ecies.PublicKey{
			X:      new(big.Int).SetBytes(pubBz[1 : 1+eciesCoordinateBytes]),
			Y:      new(big.Int).SetBytes(pubBz[1+eciesCoordinateBytes:]),
			Curve:  curve,
			Params: ecies.ECIES_AES128_SHA256,
		}

		// a key file written before the coordinates were encoded at fixed width
		// holds a coordinate multiplied by a power of 256, which is off the curve
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return fmt.Errorf("ecies pub key %d is not on the secp256k1 curve", i+1)
		}

		key.ECIESPubs[i] = pub
	}

	if aux.ID < 1 || aux.ID > len(key.ECIESPubs) {
		return fmt.Errorf("cosigner id %d out of range for %d ecies pub keys", aux.ID, len(key.ECIESPubs))
	}

	key.ECIESKey = &ecies.PrivateKey{
		PublicKey: *key.ECIESPubs[aux.ID-1],
		D:         new(big.Int).SetBytes(aux.ECIESKey),
	}

	return nil
}

// LoadCosignerECIESKey loads a CosignerECIESKey from file.
func LoadCosignerECIESKey(file string) (CosignerECIESKey, error) {
	pvKey := CosignerECIESKey{}
	keyJSONBytes, err := os.ReadFile(file)
	if err != nil {
		return pvKey, err
	}

	err = json.Unmarshal(keyJSONBytes, &pvKey)
	if err != nil {
		return pvKey, err
	}

	return pvKey, nil
}

// NewCosignerSecurityECIES creates a new CosignerSecurityECIES.
func NewCosignerSecurityECIES(key CosignerECIESKey) *CosignerSecurityECIES {
	c := &CosignerSecurityECIES{
		key:          key,
		eciesPubKeys: make(map[int]CosignerECIESPubKey, len(key.ECIESPubs)),
	}

	for i, pubKey := range key.ECIESPubs {
		c.eciesPubKeys[i+1] = CosignerECIESPubKey{
			ID:        i + 1,
			PublicKey: pubKey,
		}
	}

	return c
}

// GetID returns the ID of the cosigner.
func (c *CosignerSecurityECIES) GetID() int {
	return c.key.ID
}

// EncryptAndSign encrypts the nonce and signs it for authentication.
func (c *CosignerSecurityECIES) EncryptAndSign(id int, noncePub []byte, nonceShare []byte) (CosignerNonce, error) {
	nonce := CosignerNonce{
		SourceID: c.key.ID,
	}

	// grab the cosigner info for the ID being requested
	pubKey, ok := c.eciesPubKeys[id]
	if !ok {
		return nonce, fmt.Errorf("unknown cosigner ID: %d", id)
	}

	var encryptedPub []byte
	var encryptedShare []byte
	var eg errgroup.Group

	eg.Go(func() (err error) {
		encryptedShare, err = ecies.Encrypt(rand.Reader, pubKey.PublicKey, nonceShare, nil, nil)
		return err
	})

	eg.Go(func() (err error) {
		encryptedPub, err = ecies.Encrypt(rand.Reader, pubKey.PublicKey, noncePub, nil, nil)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nonce, err
	}

	nonce.PubKey = encryptedPub
	nonce.Share = encryptedShare

	// sign the response payload with our private key
	// cosigners can verify the signature to confirm sender validity

	jsonBytes, err := cometjson.Marshal(nonce)
	if err != nil {
		return nonce, err
	}

	hash := sha256.Sum256(jsonBytes)
	signature, err := ecdsa.SignASN1(
		rand.Reader,
		c.key.ECIESKey.ExportECDSA(),
		hash[:],
	)
	if err != nil {
		return nonce, err
	}

	nonce.DestinationID = id
	nonce.Signature = signature

	return nonce, nil
}

// DecryptAndVerify decrypts the nonce and verifies
// the signature to authenticate the source cosigner.
func (c *CosignerSecurityECIES) DecryptAndVerify(
	id int,
	encryptedNoncePub []byte,
	encryptedNonceShare []byte,
	signature []byte,
) ([]byte, []byte, error) {
	pubKey, ok := c.eciesPubKeys[id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown cosigner: %d", id)
	}

	digestMsg := CosignerNonce{
		SourceID: id,
		PubKey:   encryptedNoncePub,
		Share:    encryptedNonceShare,
	}

	digestBytes, err := cometjson.Marshal(digestMsg)
	if err != nil {
		return nil, nil, err
	}

	digest := sha256.Sum256(digestBytes)

	validSignature := ecdsa.VerifyASN1(pubKey.PublicKey.ExportECDSA(), digest[:], signature)
	if !validSignature {
		return nil, nil, fmt.Errorf("signature is invalid")
	}

	var eg errgroup.Group

	var noncePub []byte
	var nonceShare []byte

	eg.Go(func() (err error) {
		noncePub, err = c.key.ECIESKey.Decrypt(encryptedNoncePub, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt nonce pub: %w", err)
		}
		return nil
	})

	eg.Go(func() (err error) {
		nonceShare, err = c.key.ECIESKey.Decrypt(encryptedNonceShare, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt nonce share: %w", err)
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return nil, nil, err
	}

	return noncePub, nonceShare, nil
}
