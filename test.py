from scryptlib import (
        compile_contract, build_contract_class, build_type_classes
        )


if __name__ == '__main__':

    contract = './P2GenericECDSAPubKey.scrypt' 

    compiler_result = compile_contract(contract, debug=False)
    desc = compiler_result.to_desc()

    # Load desc instead:
    #with open('./out/checksig_desc.json', 'r') as f:
    #    desc = json.load(f)
    

    type_classes = build_type_classes(desc)

    P2PK = build_contract_class(desc)
