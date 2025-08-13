use ring_lwe::{
    decrypt::decrypt_bytes, encrypt::encrypt_bytes, keygen::keygen_bytes, utils::Parameters,
};

#[quickcheck_macros::quickcheck]
pub fn qc_test_basic(mut message: Vec<u8>) {
    message.push(1);
    let seed = None;
    let params = Parameters::default();
    let keypair = keygen_bytes(&params, seed);
    let pk = keypair.public;
    let sk = keypair.secret;
    let ciphertext = encrypt_bytes(&pk, &message, &params, seed);
    let decrypted_message = decrypt_bytes(&sk, &ciphertext, &params);
    assert_eq!(message, decrypted_message, "test failed");
}
