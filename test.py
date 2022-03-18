from bitcoinx import PrivateKey, sha256, SigHash
from scryptlib import (
        compile_contract, build_contract_class, build_type_classes,
        create_dummy_input_context, get_preimage_from_input_context,
        SigHashPreimage
        )


if __name__ == '__main__':
    key_priv = PrivateKey.from_arbitrary_bytes(b'test123')
    key_pub = key_priv.public_key

    contract = './P2GenericECDSAPubKey.scrypt' 

    compiler_result = compile_contract(contract, debug=False)
    desc = compiler_result.to_desc()

    # Load desc instead:
    #with open('./out/checksig_desc.json', 'r') as f:
    #    desc = json.load(f)
    
    type_classes = build_type_classes(desc)

    P2PK = build_contract_class(desc)
    p2pk = P2PK(key_pub)

    context = create_dummy_input_context()
    context.utxo.script_pubkey = p2pk.locking_script
    sighash_flag = SigHash(SigHash.ALL | SigHash.FORKID)
    preimage = get_preimage_from_input_context(context, sighash_flag)

    ### Derive proof:
    r = PrivateKey.from_arbitrary_bytes(b'123test321')

    A = r.public_key
    G = PrivateKey.from_int(1).public_key
    st = G.to_bytes(compressed=False) + key_pub.to_bytes(compressed=False)

    e = sha256(preimage + st + A.to_bytes(compressed=False))
    e = PrivateKey(e)
    z = key_priv.multiply(e._secret).add(r._secret)

    assert p2pk.unlock(e.to_int(), z.to_int(), SigHashPreimage(preimage)).verify(context)

