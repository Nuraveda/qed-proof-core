"""The KMS signing path, exercised with a LOCAL secp256k1 key through the exact same DER → low-s → recovery code."""
import rlp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from eth_hash.auto import keccak
from eth_keys import keys as eth_keys

from poaw_node.anchoring import eth


def local_signer():
    sk = ec.generate_private_key(ec.SECP256K1())
    pub = sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    # Same contract as KMS ECDSA_SHA_256 + MessageType DIGEST: sign the 32 bytes as a prehashed digest, return DER.
    return eth.EthSigner(eth.address_from_uncompressed(pub), lambda d: sk.sign(d, ec.ECDSA(Prehashed(hashes.SHA256()))))


def test_signed_1559_tx_recovers_to_the_signer_and_s_is_low():
    s = local_signer()
    tx = {"chainId": 84532, "nonce": 7, "maxPriorityFeePerGas": 10**6, "maxFeePerGas": 3 * 10**7, "gas": 150_000,
          "to": eth.EAS, "value": 0, "data": b"\x12\x34"}
    for _ in range(20):  # enough runs to hit both recovery parities and the high-s branch
        raw, h = eth.sign_1559(tx, s)
        b = bytes.fromhex(raw[2:])
        assert b[0] == 2 and keccak(b).hex() == h[2:]
        *fields, v, r, sig_s = rlp.decode(b[1:])
        assert int.from_bytes(sig_s, "big") <= eth.SECP256K1_N // 2
        digest = keccak(b"\x02" + rlp.encode(fields))
        sig = eth_keys.Signature(vrs=(int.from_bytes(v or b"\x00", "big"), int.from_bytes(r, "big"), int.from_bytes(sig_s, "big")))
        assert sig.recover_public_key_from_msg_hash(digest).to_checksum_address() == s.address


def test_a_signature_from_another_key_is_refused():
    good, other = local_signer(), local_signer()
    imposter = eth.EthSigner(good.address, other.sign_digest)
    try:
        imposter.vrs(keccak(b"x"))
        raise AssertionError("must refuse")
    except RuntimeError:
        pass


def test_anchor_data_round_trips_and_schema_uid_is_stable():
    d = eth.anchor_data(b"\x01" * 32, 9, b"\x02" * 32, 5, b"\x03" * 32, "poaw/0.1")
    back = eth.decode_anchor_data(d)
    assert back["tree_size"] == 9 and back["root_hash"] == b"\x02" * 32 and back["spec_version"] == "poaw/0.1"
    # Pinned literal, computed independently: keccak256(schema ++ zero resolver ++ revocable=false). Live checkers match it.
    assert eth.schema_uid(eth.ANCHOR_SCHEMA).hex() == "8c2390b3ccbad40acc0b8bd80ddcaff120854e94b881fc226924c51cde0a28ec"
    assert eth.schema_uid(eth.ANCHOR_SCHEMA) == keccak(eth.ANCHOR_SCHEMA.encode() + b"\x00" * 20 + b"\x00")
    assert len(eth.attest_calldata(eth.schema_uid(eth.ANCHOR_SCHEMA), d)) > 4


def test_local_signer_signs_a_transaction_that_recovers_to_its_address():
    s = eth.local_signer(bytes.fromhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"))
    assert s.address == "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"  # the well-known test key's address
    raw, h = eth.sign_1559({"chainId": 84532, "nonce": 0, "maxPriorityFeePerGas": 1, "maxFeePerGas": 2, "gas": 21000,
                            "to": "0x" + "00" * 20, "data": "0x"}, s)
    assert raw.startswith("0x02") and len(h) == 66


def test_local_signer_rejects_a_bad_key():
    import pytest
    with pytest.raises(ValueError):
        eth.local_signer(b"short")
