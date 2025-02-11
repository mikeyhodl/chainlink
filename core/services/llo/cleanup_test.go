package llo

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/libocr/offchainreporting2plus/ocr3types"
	"github.com/smartcontractkit/libocr/offchainreporting2plus/types"
	ocrtypes "github.com/smartcontractkit/libocr/offchainreporting2plus/types"

	llotypes "github.com/smartcontractkit/chainlink-common/pkg/types/llo"
	"github.com/smartcontractkit/chainlink/v2/core/internal/testutils"
	"github.com/smartcontractkit/chainlink/v2/core/internal/testutils/pgtest"
	"github.com/smartcontractkit/chainlink/v2/core/logger"
	"github.com/smartcontractkit/chainlink/v2/core/services/llo/mercurytransmitter"
)

func makeSampleTransmissions(n int) []*mercurytransmitter.Transmission {
	transmissions := make([]*mercurytransmitter.Transmission, n)
	for i := 0; i < n; i++ {
		transmissions[i] = makeSampleTransmission(uint64(i), "http://example.com/foo") //nolint:gosec // G115 don't care in test code
	}
	return transmissions
}

func makeSampleTransmission(seqNr uint64, sURL string) *mercurytransmitter.Transmission {
	return &mercurytransmitter.Transmission{
		ServerURL:    sURL,
		ConfigDigest: types.ConfigDigest{0x0, 0x9, 0x57, 0xdd, 0x2f, 0x63, 0x56, 0x69, 0x34, 0xfd, 0xc2, 0xe1, 0xcd, 0xc1, 0xe, 0x3e, 0x25, 0xb9, 0x26, 0x5a, 0x16, 0x23, 0x91, 0xa6, 0x53, 0x16, 0x66, 0x59, 0x51, 0x0, 0x28, 0x7c},
		SeqNr:        seqNr,
		Report: ocr3types.ReportWithInfo[llotypes.ReportInfo]{
			Report: ocrtypes.Report{0x0, 0x3, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x66, 0xde, 0xf5, 0xba, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x66, 0xde, 0xf5, 0xba, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1e, 0x8e, 0x95, 0xcf, 0xb5, 0xd8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1a, 0xd0, 0x1c, 0x67, 0xa9, 0xcf, 0xb3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x66, 0xdf, 0x3, 0xca, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x1c, 0x93, 0x6d, 0xa4, 0xf2, 0x17, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x14, 0x8d, 0x9a, 0xc1, 0xd9, 0x6f, 0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1b, 0x40, 0x5c, 0xcf, 0xa1, 0xbc, 0x63, 0xc0, 0x0},
			Info: llotypes.ReportInfo{
				LifeCycleStage: llotypes.LifeCycleStage("production"),
				ReportFormat:   llotypes.ReportFormatEVMPremiumLegacy,
			},
		},
		Sigs: []types.AttributedOnchainSignature{types.AttributedOnchainSignature{Signature: []uint8{0x9d, 0xab, 0x8f, 0xa7, 0xca, 0x7, 0x62, 0x57, 0xf7, 0x11, 0x2c, 0xb7, 0xf3, 0x49, 0x37, 0x12, 0xbd, 0xe, 0x14, 0x27, 0xfc, 0x32, 0x5c, 0xec, 0xa6, 0xb9, 0x7f, 0xf9, 0xd7, 0x7b, 0xa6, 0x36, 0x30, 0x9d, 0x84, 0x29, 0xbf, 0xd4, 0xeb, 0xc5, 0xc9, 0x29, 0xef, 0xdd, 0xd3, 0x2f, 0xa6, 0x25, 0x63, 0xda, 0xd9, 0x2c, 0xa1, 0x4a, 0xba, 0x75, 0xb2, 0x85, 0x25, 0x8f, 0x2b, 0x84, 0xcd, 0x99, 0x1}, Signer: 0x1}, types.AttributedOnchainSignature{Signature: []uint8{0x9a, 0x47, 0x4a, 0x3, 0x1a, 0x95, 0xcf, 0x46, 0x10, 0xaf, 0xcc, 0x90, 0x49, 0xb2, 0xce, 0xbf, 0x63, 0xaa, 0xc7, 0x25, 0x4d, 0x2a, 0x8, 0x36, 0xda, 0xd5, 0x9f, 0x9d, 0x63, 0x69, 0x22, 0xb3, 0x36, 0xd9, 0x6e, 0xf, 0xae, 0x7b, 0xd1, 0x61, 0x59, 0xf, 0x36, 0x4a, 0x22, 0xec, 0xde, 0x45, 0x32, 0xe0, 0x5b, 0x5c, 0xe3, 0x14, 0x29, 0x4, 0x60, 0x7b, 0xce, 0xa3, 0x89, 0x6b, 0xbb, 0xe0, 0x0}, Signer: 0x3}},
	}
}

func Test_Cleanup(t *testing.T) {
	ctx := testutils.Context(t)

	lp := &mockLogPoller{}
	ds := pgtest.NewSqlxDB(t)

	addr1 := common.Address{1, 2, 3}
	addr2 := common.Address{4, 5, 6}
	donID1 := uint32(1)
	donID2 := uint32(2)
	chainSelector := uint64(3)

	// add some channel definitions
	cdcorm := NewChainScopedORM(ds, chainSelector)
	{
		err := cdcorm.StoreChannelDefinitions(ctx, addr1, donID1, 1, llotypes.ChannelDefinitions{}, 1)
		require.NoError(t, err)
		err = cdcorm.StoreChannelDefinitions(ctx, addr2, donID2, 1, llotypes.ChannelDefinitions{}, 1)
		require.NoError(t, err)
	}

	// add some transmissions

	torm1 := mercurytransmitter.NewORM(ds, donID1)
	srvURL1 := "http://example.com/foo"
	srvURL2 := "http://example.test/bar"
	{
		err := torm1.Insert(ctx, []*mercurytransmitter.Transmission{makeSampleTransmission(1, srvURL1), makeSampleTransmission(1, srvURL2)})
		require.NoError(t, err)
	}

	torm2 := mercurytransmitter.NewORM(ds, donID2)
	{
		err := torm2.Insert(ctx, []*mercurytransmitter.Transmission{makeSampleTransmission(2, srvURL1), makeSampleTransmission(2, srvURL2)})
		require.NoError(t, err)
	}

	err := Cleanup(ctx, lp, addr1, donID1, ds, chainSelector)
	require.NoError(t, err)

	t.Run("unregisters filter", func(t *testing.T) {
		assert.Equal(t, []string{"OCR3 LLO ChannelDefinitionCachePoller - 0x0102030000000000000000000000000000000000:1"}, lp.unregisteredFilterNames)
	})
	t.Run("removes channel definitions", func(t *testing.T) {
		pd, err := cdcorm.LoadChannelDefinitions(ctx, addr1, donID1)
		require.NoError(t, err)
		assert.Nil(t, pd)
		pd, err = cdcorm.LoadChannelDefinitions(ctx, addr2, donID2)
		require.NoError(t, err)
		assert.NotNil(t, pd)
	})
	t.Run("does not remove transmissions", func(t *testing.T) {
		trs, err := torm1.Get(ctx, srvURL1, 10, 0)
		require.NoError(t, err)
		assert.Len(t, trs, 1)
		trs, err = torm1.Get(ctx, srvURL2, 10, 0)
		require.NoError(t, err)
		assert.Len(t, trs, 1)

		trs, err = torm2.Get(ctx, srvURL1, 10, 0)
		require.NoError(t, err)
		assert.Len(t, trs, 1)
		trs, err = torm2.Get(ctx, srvURL2, 10, 0)
		require.NoError(t, err)
		assert.Len(t, trs, 1)
	})
}

func Test_TransmissionReaper(t *testing.T) {
	ds := pgtest.NewSqlxDB(t)
	lggr := logger.TestLogger(t)
	tr := &transmissionReaper{ds: ds, lggr: lggr, maxAge: 24 * time.Hour}
	ctx := testutils.Context(t)

	const n = 13

	transmissions := makeSampleTransmissions(n)
	torm := mercurytransmitter.NewORM(ds, 1)
	err := torm.Insert(testutils.Context(t), transmissions)
	require.NoError(t, err)
	pgtest.MustExec(t, ds, `
UPDATE llo_mercury_transmit_queue 
SET inserted_at = NOW() - INTERVAL '48 hours'
WHERE transmission_hash IN (
    SELECT transmission_hash FROM llo_mercury_transmit_queue 
    LIMIT 5
);
`)

	// test batching
	d, err := tr.reapStale(ctx, n/3)
	require.NoError(t, err)
	assert.Equal(t, int64(5), d)

	pgtest.MustExec(t, ds, "UPDATE llo_mercury_transmit_queue SET inserted_at = NOW() - INTERVAL '48 hours'")

	d, err = tr.reapStale(ctx, n/3)
	require.NoError(t, err)
	assert.Equal(t, int64(n-5), d)
}
