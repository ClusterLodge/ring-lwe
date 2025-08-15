    use ring_lwe::decrypt::{decrypt, decrypt_bytes};
    use ring_lwe::encrypt::{encrypt, encrypt_bytes};
    use ring_lwe::keygen::{keygen, keygen_bytes};
    use ring_lwe::utils::{
        gen_uniform_poly, mod_coeffs, nearest_int, polyadd, polymul, polymul_fast, NttPlan, Parameters
    };
    use ntt::omega;
    use polynomial_ring::Polynomial;

    // Test for basic keygen/encrypt/decrypt of a message
    #[test]
    pub fn test_basic() {
        let seed = None; //set the random seed
        let message = "hello".as_bytes();
        let params = Parameters::default();
        let keypair = keygen_bytes(&params, seed);
        let pk = keypair.public;
        let sk = keypair.secret;
        let ciphertext_string = encrypt_bytes(&pk, &message, &params, seed);
        let decrypted_message = decrypt_bytes(&sk, &ciphertext_string, &params);
        assert_eq!(message, decrypted_message, "test failed");
    }

    // Test homomorphic addition property: ensure sum of encrypted plaintexts decrypts to plaintext sum
    #[test]
    pub fn test_hom_add() {
        let seed = None; //set the random seed
        let params = Parameters::default(); // Adjust this if needed
        let (t, f) = (params.t, &params.f);
        let ntt_plan = NttPlan::try_new(params.n, params.q.try_into().unwrap())
            .expect("Failed to create NTT plan");

        // Create polynomials from ints
        let m0_poly = Polynomial::new(vec![1, 0, 1]);
        let m1_poly = Polynomial::new(vec![0, 0, 1]);

        let plaintext_sum = polyadd(&m0_poly, &m1_poly, t, &f);
        let (pk, sk) = keygen(&params, seed, &ntt_plan);

        // Encrypt plaintext messages
        let u = encrypt(&pk, &m0_poly, &params, seed, &ntt_plan);
        let v = encrypt(&pk, &m1_poly, &params, seed, &ntt_plan);

        // Compute sum of encrypted data
        let ciphertext_sum = [&u[0] + &v[0], &u[1] + &v[1]];

        // Decrypt ciphertext sum u+v
        let decrypted_sum = decrypt(&sk, &ciphertext_sum, &params, &ntt_plan);

        assert_eq!(
            decrypted_sum, plaintext_sum,
            "test failed: {} != {}",
            decrypted_sum, plaintext_sum
        );
    }

    // Test homomorphic multiplication property: product of encrypted plaintexts should decrypt to plaintext product
    #[ignore]
    #[test]
    pub fn test_hom_prod() {
        let seed = None; //set the random seed
        let mut params = Parameters::default();
        let (q, t, f) = (params.q, params.t, &params.f);
        params.q = q * q;
        params.omega = omega(params.q, 2 * params.n);
        let ntt_plan = NttPlan::try_new(params.n, params.q.try_into().unwrap())
            .expect("Failed to create NTT plan");

        //create polynomials from ints
        let m0_poly = Polynomial::new(vec![1, 0, 1]);
        let m1_poly = Polynomial::new(vec![0, 0, 1]);

        // Generate the keypair
        let (pk, sk) = keygen(&params, seed, &ntt_plan);

        // Encrypt plaintext messages
        let u = encrypt(&pk, &m0_poly, &params, seed, &ntt_plan);
        let v = encrypt(&pk, &m1_poly, &params, seed, &ntt_plan);

        let plaintext_prod = polymul(&m0_poly, &m1_poly, t, &f);
        //compute product of encrypted data, using non-standard multiplication
        let c0 = polymul(&u[0], &v[0], params.q, &f);
        let u0v1 = &polymul(&u[0], &v[1], params.q, &f);
        let u1v0 = &polymul(&u[1], &v[0], params.q, &f);
        let c1 = polyadd(u0v1, u1v0, params.q, &f);
        let c2 = polymul(&u[1], &v[1], params.q, &f);
        //compute c0 + c1*s + c2*s*s
        let c1_sk = &polymul(&c1, &sk, params.q, &f);
        let c2_sk_squared = &polymul(&polymul(&c2, &sk, params.q, &f), &sk, params.q, &f);
        let ciphertext_prod = polyadd(
            &polyadd(&c0, c1_sk, params.q, &f),
            c2_sk_squared,
            params.q,
            &f,
        );
        //let delta = q / t, divide coeffs by 1 / delta^2
        let delta = q / t;
        let decrypted_prod = mod_coeffs(
            Polynomial::new(
                ciphertext_prod
                    .coeffs()
                    .iter()
                    .map(|&coeff| nearest_int(coeff, delta * delta))
                    .collect::<Vec<_>>(),
            ),
            t,
        );

        assert_eq!(
            plaintext_prod, decrypted_prod,
            "test failed: {} != {}",
            plaintext_prod, decrypted_prod
        );
    }

    // Test fast polynomial multiplication with the NTT for uniformly random polynomials degree n
    #[test]
    pub fn test_polymul_fast_uniform() {
        let seed = None; //set the random seed
        let params = Parameters::default();
        let ntt_plan = NttPlan::try_new(params.n, params.q.try_into().unwrap())
            .expect("Failed to create NTT plan");

        // Input polynomials (padded to length `n`)
        let a = gen_uniform_poly(params.n, params.q, seed);
        let b = gen_uniform_poly(params.n, params.q, seed);

        let c_std = polymul(&a, &b, params.q, &params.f);
        let c_fast = polymul_fast(&a, &b, params.q, &ntt_plan);

        assert_eq!(c_std, c_fast, "test failed: {} != {}", c_std, c_fast);
    }

    #[test]
    fn test_ct_len() {
        let seed = None; //set the random seed
        let params = Parameters::default();
        let message_256 = concat!(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .as_bytes();
        // params.n is bit length.
        assert_eq!(
            8 * message_256.len(),
            2 * params.n,
            "invalid test: data is expected to be 2 blocks long"
        );
        let keypair = keygen_bytes(&params, seed);
        let pk = keypair.public;
        let ciphertext = encrypt_bytes(&pk, &message_256, &params, seed);
        // two block length; add extra 8 bytes for bincode metadata.
        // So, the cyphertext is 2 * 8 * 8 = 128 times larger than the plaintext.
        assert_eq!(ciphertext.len(), 128 * message_256.len() + 8);
    }
