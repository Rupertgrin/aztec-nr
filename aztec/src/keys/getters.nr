use dep::protocol_types::{
    header::Header, 
    abis::validation_requests::KeyValidationRequest, 
    address::AztecAddress,
    constants::CANONICAL_KEY_REGISTRY_ADDRESS, 
    grumpkin_point::GrumpkinPoint,
    storage::map::derive_storage_slot_in_map
};
use crate::{
    context::PrivateContext,
    oracle::{
        keys::get_public_keys_and_partial_address, 
        key_validation_request::get_key_validation_request
    },
    keys::{
        public_keys::PublicKeys, 
        constants::{NULLIFIER_INDEX, INCOMING_INDEX}
    },
    state_vars::{
        shared_mutable::shared_mutable_private_getter::SharedMutablePrivateGetter
    }
};

const DELAY: u64 = 5;

trait KeyGetters {
    fn get_ivpk_m(&self, context: &mut PrivateContext, address: AztecAddress) -> GrumpkinPoint;
    fn get_npk_m(&self, context: &mut PrivateContext, address: AztecAddress) -> GrumpkinPoint;
    fn get_npk_m_hash(&self, context: &mut PrivateContext, address: AztecAddress) -> Field;
}

impl KeyGetters for Header {
    fn get_ivpk_m(&self, context: &mut PrivateContext, address: AztecAddress) -> GrumpkinPoint {
        self.get_master_key(context, address, INCOMING_INDEX)
    }

    fn get_npk_m_hash(&self, context: &mut PrivateContext, address: AztecAddress) -> Field {
        self.get_master_key(context, address, NULLIFIER_INDEX).hash()
    }

    fn get_npk_m(&self, context: &mut PrivateContext, address: AztecAddress) -> GrumpkinPoint {
        self.get_master_key(context, address, NULLIFIER_INDEX)
    }
}

impl Header {
    fn get_master_key(
        &self,
        context: &mut PrivateContext,
        address: AztecAddress,
        key_index: Field,
    ) -> GrumpkinPoint {
        let key = self.fetch_key_from_registry(context, key_index, address);
        if key.is_zero() {
            let keys = self.fetch_and_constrain_keys(address);
            keys.get_key_by_index(key_index)
        } else {
            key
        }
    }

    fn fetch_key_from_registry(
        &self,
        context: &mut PrivateContext,
        key_index: Field,
        address: AztecAddress,
    ) -> GrumpkinPoint {
        let x_coordinate_map_slot = key_index * 2 + 1;
        let y_coordinate_map_slot = x_coordinate_map_slot + 1;
        let x_coordinate_derived_slot = derive_storage_slot_in_map(x_coordinate_map_slot, address);
        let y_coordinate_derived_slot = derive_storage_slot_in_map(y_coordinate_map_slot, address);

        let x_coordinate_registry: SharedMutablePrivateGetter<Field, DELAY> = SharedMutablePrivateGetter::new(
            context,
            AztecAddress::from_field(CANONICAL_KEY_REGISTRY_ADDRESS),
            x_coordinate_derived_slot
        );
        let y_coordinate_registry: SharedMutablePrivateGetter<Field, DELAY> = SharedMutablePrivateGetter::new(
            context,
            AztecAddress::from_field(CANONICAL_KEY_REGISTRY_ADDRESS),
            y_coordinate_derived_slot
        );
        let x_coordinate = x_coordinate_registry.get_value_in_private(self);
        let y_coordinate = y_coordinate_registry.get_value_in_private(self);

        GrumpkinPoint::new(x_coordinate, y_coordinate)
    }

    fn fetch_and_constrain_keys(&self, address: AztecAddress) -> PublicKeys {
        let (public_keys, partial_address) = get_public_keys_and_partial_address(address);

        let computed_address = AztecAddress::compute(public_keys.hash(), partial_address);

        assert!(computed_address.eq(&address));

        public_keys
    }
}

pub fn get_nsk_app(npk_m_hash: Field) -> Field {
    get_key_validation_request(npk_m_hash, NULLIFIER_INDEX).sk_app
}
