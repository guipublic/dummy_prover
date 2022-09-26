use acvm::acir::circuit::gate::GadgetCall;
use acvm::acir::native_types::Witness;
use acvm::acir::OPCODE;
use acvm::{pwg, FieldElement};
use blake2::Blake2s;
use blake2::Digest;
use std::collections::BTreeMap;
pub struct GadgetCaller;

impl GadgetCaller {
    pub fn solve_gadget_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gadget_call: &GadgetCall,
    ) -> Result<(), OPCODE> {
        match gadget_call.name {
            OPCODE::SHA256 => pwg::hash::sha256(initial_witness, gadget_call),
            OPCODE::Blake2s => pwg::hash::blake2s(initial_witness, gadget_call),
            OPCODE::EcdsaSecp256k1 => {
                pwg::signature::ecdsa::secp256k1_prehashed(initial_witness, gadget_call)
            }
            OPCODE::AES => return Err(gadget_call.name),
            OPCODE::MerkleMembership => {
                let result = FieldElement::one();

                initial_witness.insert(gadget_call.outputs[0], result);
            }
            OPCODE::SchnorrVerify => {
                let result = FieldElement::one();

                initial_witness.insert(gadget_call.outputs[0], result);
            }
            OPCODE::Pedersen => {
                let (res_x, res_y) = (FieldElement::zero(), FieldElement::zero());
                initial_witness.insert(gadget_call.outputs[0], res_x);
                initial_witness.insert(gadget_call.outputs[1], res_y);
            }
            OPCODE::HashToField => {
                // Deal with Blake2s -- XXX: It's not possible for pwg to know that it is Blake2s
                // We need to get this method from the backend
                let mut hasher = Blake2s::new();

                // 0. For each input in the vector of inputs, check if we have their witness assignments (Can do this outside of match, since they all have inputs)
                for input_index in gadget_call.inputs.iter() {
                    let witness = &input_index.witness;
                    let num_bits = input_index.num_bits;

                    let witness_assignment = initial_witness.get(witness);
                    let assignment = match witness_assignment {
                        None => panic!("cannot find witness assignment for {:?}", witness),
                        Some(assignment) => assignment,
                    };

                    let bytes = assignment.fetch_nearest_bytes(num_bits as usize);

                    hasher.update(bytes);
                }
                let result = hasher.finalize();

                let reduced_res = FieldElement::from_be_bytes_reduce(&result);
                assert_eq!(gadget_call.outputs.len(), 1);

                initial_witness.insert(gadget_call.outputs[0], reduced_res);
            }
            OPCODE::FixedBaseScalarMul => {
                let (pub_x, pub_y) = (FieldElement::zero(), FieldElement::zero());
                initial_witness.insert(gadget_call.outputs[0], pub_x);
                initial_witness.insert(gadget_call.outputs[1], pub_y);
            }
            OPCODE::ToBits => unreachable!(),
        }
        Ok(())
    }
}
