package signer

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	cometlog "github.com/cometbft/cometbft/libs/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// noncelessCosigner refuses every nonce request, so a threshold that includes
// it can never be reached through the fallback.
type noncelessCosigner struct {
	Cosigner
}

func (c *noncelessCosigner) GetNonces(context.Context, []uuid.UUID) (CosignerUUIDNoncesMultiple, error) {
	return nil, errors.New("nonce request refused by test cosigner")
}

// A nonce fallback that times out must not leave anything behind: every
// goroutine it spawns has to end once the cosigner calls return. A waiter
// pinned on a count that can never be reached accumulates one leaked goroutine
// per failed fallback, exactly when the cluster is already struggling.
func TestNonceFallbackTimeoutDoesNotLeakGoroutines(t *testing.T) {
	cosigners, _ := getTestLocalCosigners(t, 2, 2)
	leader := &MockLeader{id: 1}
	validator := NewThresholdValidator(
		cometlog.NewNopLogger(), cosigners[0].config, 2, 50*time.Millisecond, 1,
		cosigners[0], []Cosigner{&noncelessCosigner{Cosigner: cosigners[1]}}, leader,
	)
	leader.leader = validator
	t.Cleanup(validator.Stop)
	require.NoError(t, validator.LoadSignStateIfNecessary(testChainID))

	const rounds = 8
	baseline := runtime.NumGoroutine()

	for range rounds {
		_, err := validator.getNoncesFallback(context.Background(), 1)
		require.Error(t, err, "the threshold is unreachable, the fallback must time out")
	}

	// The worker goroutines end as soon as their cosigner calls return; only a
	// leaked waiter survives. Allow the workers a moment to drain, and report
	// the count observed at failure time rather than before the wait.
	var leaked int
	require.Eventually(t, func() bool {
		leaked = runtime.NumGoroutine() - baseline
		return leaked <= 2
	}, 2*time.Second, 20*time.Millisecond,
		"leaked goroutines across %d timed-out fallbacks (last count: see condition)", rounds)
	require.LessOrEqual(t, leaked, 2)
}
