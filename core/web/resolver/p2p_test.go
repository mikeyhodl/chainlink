package resolver

import (
	"encoding/json"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink/core/services/keystore"
	"github.com/smartcontractkit/chainlink/core/services/keystore/keys/p2pkey"
)

func TestGetP2PKeys(t *testing.T) {
	t.Parallel()

	query := `
		query GetP2PKeys {
			p2pKeys {
				results {
					id
					peerId
					publicKey
				}
			}
		}
	`

	fakeKeys := []p2pkey.KeyV2{}
	expectedKeys := []map[string]string{}
	for i := 0; i < 2; i++ {
		k, err := p2pkey.NewV2()
		assert.NoError(t, err)
		fakeKeys = append(fakeKeys, k)
		expectedKeys = append(expectedKeys, map[string]string{
			"id":        k.ID(),
			"peerId":    k.PeerID().String(),
			"publicKey": k.PublicKeyHex(),
		})
	}

	d, err := json.Marshal(map[string]interface{}{
		"p2pKeys": map[string]interface{}{
			"results": expectedKeys,
		},
	})
	assert.NoError(t, err)
	expected := string(d)

	testCases := []GQLTestCase{
		unauthorizedTestCase(GQLTestCase{query: query}, "p2pKeys"),
		{
			name:          "success",
			authenticated: true,
			before: func(f *gqlTestFramework) {
				f.Mocks.p2p.On("GetAll").Return(fakeKeys, nil)
				f.Mocks.keystore.On("P2P").Return(f.Mocks.p2p)
				f.App.On("GetKeyStore").Return(f.Mocks.keystore)
			},
			query:  query,
			result: expected,
		},
	}

	RunGQLTests(t, testCases)
}

func TestCreateP2PKey(t *testing.T) {
	t.Parallel()

	query := `
		mutation CreateP2PKey {
			createP2PKey {
				key {
					id
					peerId
					publicKey
				}
			}
		}
	`

	fakeKey, err := p2pkey.NewV2()
	assert.NoError(t, err)

	d, err := json.Marshal(map[string]interface{}{
		"createP2PKey": map[string]interface{}{
			"key": map[string]interface{}{
				"id":        fakeKey.ID(),
				"peerId":    fakeKey.PeerID().String(),
				"publicKey": fakeKey.PublicKeyHex(),
			},
		},
	})
	assert.NoError(t, err)
	expected := string(d)

	testCases := []GQLTestCase{
		unauthorizedTestCase(GQLTestCase{query: query}, "createP2PKey"),
		{
			name:          "success",
			authenticated: true,
			before: func(f *gqlTestFramework) {
				f.Mocks.p2p.On("Create").Return(fakeKey, nil)
				f.Mocks.keystore.On("P2P").Return(f.Mocks.p2p)
				f.App.On("GetKeyStore").Return(f.Mocks.keystore)
			},
			query:  query,
			result: expected,
		},
	}

	RunGQLTests(t, testCases)
}

func TestDeleteP2PKey(t *testing.T) {
	t.Parallel()

	fakeKey, err := p2pkey.NewV2()
	assert.NoError(t, err)

	query := `
		mutation DeleteP2PKey($id: String!) {
			deleteP2PKey(id: $id) {
				... on DeleteP2PKeySuccess {
					key {
						id
						peerId
						publicKey
					}
				}

				... on NotFoundError {
					message
					code
				}
			}
		}
	`

	variables := map[string]interface{}{
		"id": fakeKey.ID(),
	}

	d, err := json.Marshal(map[string]interface{}{
		"deleteP2PKey": map[string]interface{}{
			"key": map[string]interface{}{
				"id":        fakeKey.ID(),
				"peerId":    fakeKey.PeerID().String(),
				"publicKey": fakeKey.PublicKeyHex(),
			},
		},
	})
	assert.NoError(t, err)
	expected := string(d)

	testCases := []GQLTestCase{
		unauthorizedTestCase(GQLTestCase{query: query, variables: variables}, "deleteP2PKey"),
		{
			name:          "success",
			authenticated: true,
			before: func(f *gqlTestFramework) {
				f.Mocks.p2p.On("Delete", p2pkey.PeerID(fakeKey.ID())).Return(fakeKey, nil)
				f.Mocks.keystore.On("P2P").Return(f.Mocks.p2p)
				f.App.On("GetKeyStore").Return(f.Mocks.keystore)
			},
			query:     query,
			variables: variables,
			result:    expected,
		},
		{
			name:          "not found error",
			authenticated: true,
			before: func(f *gqlTestFramework) {
				f.Mocks.p2p.
					On("Delete", p2pkey.PeerID(fakeKey.ID())).
					Return(
						p2pkey.KeyV2{},
						errors.Wrap(
							keystore.ErrMissingP2PKey,
							"unable to find P2P key with id helloWorld",
						),
					)
				f.Mocks.keystore.On("P2P").Return(f.Mocks.p2p)
				f.App.On("GetKeyStore").Return(f.Mocks.keystore)
			},
			query:     query,
			variables: variables,
			result: `{
				"deleteP2PKey": {
					"code":"NOT_FOUND",
					"message":"unable to find P2P key with id helloWorld: unable to find P2P key"
				}
			}`,
		},
	}

	RunGQLTests(t, testCases)
}
