use move0_methods::{MOVE0_ELF, MOVE0_ID};

use risc0_zkvm::{
    serde::{from_slice, to_vec},
    get_prover_impl, ProverOpts, DynProverImpl, ExecutorEnv,
    // LocalProver,
};

use move_vm_runtime::move_vm::MoveVM;
use move_binary_format::{
    errors::{VMError, VMResult},
    file_format::{
        empty_module, AbilitySet, AddressIdentifierIndex, Bytecode, CodeUnit, CompiledModule,
        CompiledScript, FieldDefinition, FunctionDefinition, FunctionHandle, FunctionHandleIndex,
        IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        SignatureToken, StructDefinition, StructFieldInformation, StructHandle, StructHandleIndex,
        TableIndex, TypeSignature, Visibility,
    },
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
    language_storage::{ModuleId, StructTag, TypeTag},
    resolver::{ModuleResolver, ResourceResolver},
    u256::U256,
    value::{serialize_values, MoveValue},
    vm_status::{StatusCode, StatusType},
};
use move_vm_types::gas::UnmeteredGasMeter;

// make a script with a given signature for main.
fn make_script(parameters: Signature) -> Vec<u8> {
    let mut blob = vec![];
    let mut signatures = vec![Signature(vec![])];
    let parameters_idx = match signatures
        .iter()
        .enumerate()
        .find(|(_, s)| *s == &parameters)
    {
        Some((idx, _)) => SignatureIndex(idx as TableIndex),
        None => {
            signatures.push(parameters);
            SignatureIndex((signatures.len() - 1) as TableIndex)
        }
    };
    CompiledScript {
        version: move_binary_format::file_format_common::VERSION_MAX,
        module_handles: vec![],
        struct_handles: vec![],
        function_handles: vec![],

        function_instantiations: vec![],

        signatures,

        identifiers: vec![],
        address_identifiers: vec![],
        constant_pool: vec![],
        metadata: vec![],

        type_parameters: vec![],
        parameters: parameters_idx,
        code: CodeUnit {
            locals: SignatureIndex(0),
            code: vec![Bytecode::LdU64(0), Bytecode::Abort],
        },
    }
    .serialize(&mut blob)
    .expect("script must serialize");
    blob
}

fn good_signatures_and_arguments() -> Vec<(Signature, Vec<MoveValue>)> {
    vec![
        // U128 arg
        (
            Signature(vec![SignatureToken::U128]),
            vec![MoveValue::U128(0)],
        ),
        // U8 arg
        (Signature(vec![SignatureToken::U8]), vec![MoveValue::U8(0)]),
        // U16 arg
        (
            Signature(vec![SignatureToken::U16]),
            vec![MoveValue::U16(0)],
        ),
        // U32 arg
        (
            Signature(vec![SignatureToken::U32]),
            vec![MoveValue::U32(0)],
        ),
        // U256 arg
        (
            Signature(vec![SignatureToken::U256]),
            vec![MoveValue::U256(U256::zero())],
        ),
        // All constants
        (
            Signature(vec![SignatureToken::Vector(Box::new(SignatureToken::Bool))]),
            vec![MoveValue::Vector(vec![
                MoveValue::Bool(false),
                MoveValue::Bool(true),
            ])],
        ),
        // All constants
        (
            Signature(vec![
                SignatureToken::Bool,
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
                SignatureToken::Address,
            ]),
            vec![
                MoveValue::Bool(true),
                MoveValue::vector_u8(vec![0, 1]),
                MoveValue::Address(AccountAddress::random()),
            ],
        ),
        // vector<vector<address>>
        (
            Signature(vec![
                SignatureToken::Bool,
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
                SignatureToken::Vector(Box::new(SignatureToken::Vector(Box::new(
                    SignatureToken::Address,
                )))),
            ]),
            vec![
                MoveValue::Bool(true),
                MoveValue::vector_u8(vec![0, 1]),
                MoveValue::Vector(vec![
                    MoveValue::Vector(vec![
                        MoveValue::Address(AccountAddress::random()),
                        MoveValue::Address(AccountAddress::random()),
                    ]),
                    MoveValue::Vector(vec![
                        MoveValue::Address(AccountAddress::random()),
                        MoveValue::Address(AccountAddress::random()),
                    ]),
                    MoveValue::Vector(vec![
                        MoveValue::Address(AccountAddress::random()),
                        MoveValue::Address(AccountAddress::random()),
                    ]),
                ]),
            ],
        ),
        //
        // Vector arguments
        //
        // empty vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![])],
        ),
        // one elem vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![MoveValue::Address(
                AccountAddress::random(),
            )])],
        ),
        // multiple elems vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Address,
            ))]),
            vec![MoveValue::Vector(vec![
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
                MoveValue::Address(AccountAddress::random()),
            ])],
        ),
        // empty vector of vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
            ))]),
            vec![MoveValue::Vector(vec![])],
        ),
        // multiple element vector of vector
        (
            Signature(vec![SignatureToken::Vector(Box::new(
                SignatureToken::Vector(Box::new(SignatureToken::U8)),
            ))]),
            vec![MoveValue::Vector(vec![
                MoveValue::vector_u8(vec![0, 1]),
                MoveValue::vector_u8(vec![2, 3]),
                MoveValue::vector_u8(vec![4, 5]),
            ])],
        ),
    ]
}

pub fn main() {
    // compile script into a bytecode, load input args
    // here it's just stub values
    let (script, args) = {
        let mut params = good_signatures_and_arguments();
        let (param, args) = params.pop().unwrap();
        (make_script(param.clone()), serialize_values(&args))
    };

    let env = ExecutorEnv::builder()
        .add_input(&to_vec(&script).unwrap())
        .add_input(&to_vec(&args).unwrap())
        .segment_limit_po2(15)
        .build()
        .unwrap();

    // Obtain the default prover.
    // let prover = LocalProver::new("local");
    let prover = get_prover_impl(&ProverOpts::default()).unwrap();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove_elf(env, MOVE0_ELF).unwrap();

    // TODO: Implement code for transmitting or serializing the receipt for
    // other parties to verify here

    // Optional: Verify receipt to confirm that recipients will also be able to
    // verify your receipt
    receipt.verify(MOVE0_ID).unwrap();
}
