use acvm::acir::circuit::gate::GadgetCall;
use acvm::acir::circuit::Circuit;
use acvm::acir::native_types::Witness;
use acvm::{acir, FieldElement};
use std::collections::BTreeMap;

use acvm::{Language, ProofSystemCompiler};

use crate::acvm_interop::gadget_call::GadgetCaller;
use crate::Plonk;

impl ProofSystemCompiler for Plonk {
    fn prove_with_meta(
        &self,
        _circuit: Circuit,
        _witness_values: BTreeMap<Witness, FieldElement>,
    ) -> Vec<u8> {
        vec![72, 69, 76, 76, 76, 76, 76]
    }

    fn verify_from_cs(
        &self,
        _proof: &[u8],
        _public_inputs: Vec<FieldElement>,
        _circuit: Circuit,
    ) -> bool {
        //dummy verifier
        true
    }

    fn np_language(&self) -> Language {
        Language::PLONKCSat { width: 3 }
    }
}

use acvm::SmartContract;

impl SmartContract for Plonk {
    fn eth_contract_from_cs(&self, _circuit: Circuit) -> String {
        todo!();
    }
}

use acvm::PartialWitnessGenerator;

impl PartialWitnessGenerator for Plonk {
    fn solve_gadget_call(
        initial_witness: &mut BTreeMap<Witness, FieldElement>,
        gc: &GadgetCall,
    ) -> Result<(), acir::OPCODE> {
        GadgetCaller::solve_gadget_call(initial_witness, gc)
    }
}
