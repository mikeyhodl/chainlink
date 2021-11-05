package resolver

import "github.com/smartcontractkit/chainlink/core/services/keystore/keys/p2pkey"

type P2PKey struct {
	id        string
	peerID    string
	publicKey string
}

func (k P2PKey) ID() string {
	return k.id
}

func (k P2PKey) PeerID() string {
	return k.peerID
}

func (k P2PKey) PublicKey() string {
	return k.publicKey
}

type P2PKeysPayloadResolver struct {
	keys []p2pkey.KeyV2
}

func NewP2PKeysPayloadResolver(keys []p2pkey.KeyV2) *P2PKeysPayloadResolver {
	return &P2PKeysPayloadResolver{keys}
}

func (r *P2PKeysPayloadResolver) Results() []P2PKey {
	results := []P2PKey{}
	for _, k := range r.keys {
		results = append(results, P2PKey{
			id:        k.ID(),
			peerID:    k.PeerID().String(),
			publicKey: k.PublicKeyHex(),
		})
	}
	return results
}

type CreateP2PKeyPayloadResolver struct {
	key p2pkey.KeyV2
}

func NewCreateP2PKeyPayloadResolver(key p2pkey.KeyV2) *CreateP2PKeyPayloadResolver {
	return &CreateP2PKeyPayloadResolver{key}
}

func (r *CreateP2PKeyPayloadResolver) Key() P2PKey {
	return P2PKey{
		id:        r.key.ID(),
		peerID:    r.key.PeerID().String(),
		publicKey: r.key.PublicKeyHex(),
	}
}

type DeleteP2PKeySuccessResolver struct {
	key p2pkey.KeyV2
}

func NewDeleteP2PKeySuccessResolver(key p2pkey.KeyV2) *DeleteP2PKeySuccessResolver {
	return &DeleteP2PKeySuccessResolver{key}
}

func (r *DeleteP2PKeySuccessResolver) Key() P2PKey {
	return P2PKey{
		id:        r.key.ID(),
		peerID:    r.key.PeerID().String(),
		publicKey: r.key.PublicKeyHex(),
	}
}

type DeleteP2PKeyPayloadResolver struct {
	key p2pkey.KeyV2
	err error
}

func NewDeleteP2PKeyPayloadResolver(key p2pkey.KeyV2, err error) *DeleteP2PKeyPayloadResolver {
	return &DeleteP2PKeyPayloadResolver{key, err}
}

func (r *DeleteP2PKeyPayloadResolver) ToDeleteP2PKeySuccess() (*DeleteP2PKeySuccessResolver, bool) {
	if r.err == nil {
		return NewDeleteP2PKeySuccessResolver(r.key), true
	}
	return nil, false
}

func (r *DeleteP2PKeyPayloadResolver) ToNotFoundError() (*NotFoundErrorResolver, bool) {
	if r.err != nil {
		return NewNotFoundError(r.err.Error()), true
	}
	return nil, false
}
