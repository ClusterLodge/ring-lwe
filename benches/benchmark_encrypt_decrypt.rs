use criterion::{criterion_group, criterion_main, Criterion};
use polynomial_ring::Polynomial;
use ring_lwe::decrypt::{decrypt, decrypt_bytes};
use ring_lwe::encrypt::{encrypt, encrypt_bytes};
use ring_lwe::keygen::{keygen, keygen_bytes};
use ring_lwe::utils::Parameters;

fn bench_encrypt(c: &mut Criterion) {
    let params = Parameters::default();
    let (pk, _) = keygen(&params, None);
    let m_b = Polynomial::new(vec![0, 1, 0, 1, 1, 0, 1, 0]); // Example binary message

    c.bench_function("encrypt", |b| b.iter(|| encrypt(&pk, &m_b, &params, None)));
}

const MESSAGE_SMALL: &str = "small";
const MESSAGE_2000: &str = concat!(
    "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean commodo ligula eget dolor. Aenean massa. Cum soc",
    "iis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Donec quam felis, ultricies nec, p",
    "ellentesque eu, pretium quis, sem. Nulla consequat massa quis enim. Donec pede justo, fringilla vel, aliquet nec,",
    " vulputate eget, arcu. In enim justo, rhoncus ut, imperdiet a, venenatis vitae, justo. Nullam dictum felis eu ped",
    "e mollis pretium. Integer tincidunt. Cras dapibus. Vivamus elementum semper nisi. Aenean vulputate eleifend tellu",
    "s. Aenean leo ligula, porttitor eu, consequat vitae, eleifend ac, enim. Aliquam lorem ante, dapibus in, viverra q",
    "uis, feugiat a, tellus. Phasellus viverra nulla ut metus varius laoreet. Quisque rutrum. Aenean imperdiet. Etiam ",
    "ultricies nisi vel augue. Curabitur ullamcorper ultricies nisi. Nam eget dui. Etiam rhoncus. Maecenas tempus, tel",
    "lus eget condimentum rhoncus, sem quam semper libero, sit amet adipiscing sem neque sed ipsum. Nam quam nunc, bla",
    "ndit vel, luctus pulvinar, hendrerit id, lorem. Maecenas nec odio et ante tincidunt tempus. Donec vitae sapien ut",
    " libero venenatis faucibus. Nullam quis ante. Etiam sit amet orci eget eros faucibus tincidunt. Duis leo. Sed fri",
    "ngilla mauris sit amet nibh. Donec sodales sagittis magna. Sed consequat, leo eget bibendum sodales, augue velit ",
    "cursus nunc, quis gravida magna mi a libero. Fusce vulputate eleifend sapien. Vestibulum purus quam, scelerisque ",
    "ut, mollis sed, nonummy id, metus. Nullam accumsan lorem in dui. Cras ultricies mi eu turpis hendrerit fringilla.",
    " Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; In ac dui quis mi consec",
    "tetuer lacinia. Nam pretium turpis et arcu. Duis arcu tortor, suscipit eget, imperdiet nec, imperdiet iaculis, ip",
    "sum. Sed aliquam ultrices mauris. Integer ante arcu, accumsan a, consectetuer eget, posuere ut, mauris. Praesent ",
    "adipiscing. Phasellus ullamcorper ipsum rutrum nunc. Nunc nonummy metus. Vestib"
);

fn bench_encrypt_bytes_small(c: &mut Criterion) {
    let params = Parameters::default();
    let keypair = keygen_bytes(&params, None);
    let pk = keypair.public;
    let message = MESSAGE_SMALL.as_bytes();

    c.bench_function("encrypt_string_small", |b| {
        b.iter(|| encrypt_bytes(&pk, &message, &params, None))
    });
}

fn bench_encrypt_bytes_2000(c: &mut Criterion) {
    let params = Parameters::default();
    let keypair = keygen_bytes(&params, None);
    let pk = keypair.public;
    let message = MESSAGE_2000.as_bytes();

    c.bench_function("encrypt_string_2000", |b| {
        b.iter(|| encrypt_bytes(&pk, &message, &params, None))
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let params = Parameters::default();
    let (pk, sk) = keygen(&params, None);
    let m_b = Polynomial::new(vec![0, 1, 0, 1, 1, 0, 1, 0]); // Example binary message
    let ct = encrypt(&pk, &m_b, &params, None);

    c.bench_function("decrypt", |b| b.iter(|| decrypt(&sk, &ct, &params)));
}

fn bench_decrypt_string_small(c: &mut Criterion) {
    let params = Parameters::default();
    let keypair = keygen_bytes(&params, None);
    let sk = keypair.secret;
    let pk = keypair.public;
    let message = MESSAGE_SMALL.as_bytes();
    let ciphertext_string = encrypt_bytes(&pk, &message, &params, None);

    c.bench_function("decrypt_string_small", |b| {
        b.iter(|| decrypt_bytes(&sk, &ciphertext_string, &params))
    });
}

fn bench_decrypt_string_2000(c: &mut Criterion) {
    let params = Parameters::default();
    let keypair = keygen_bytes(&params, None);
    let sk = keypair.secret;
    let pk = keypair.public;
    let message = MESSAGE_2000.as_bytes();
    let ciphertext_string = encrypt_bytes(&pk, &message, &params, None);

    c.bench_function("decrypt_string_2000", |b| {
        b.iter(|| decrypt_bytes(&sk, &ciphertext_string, &params))
    });
}

criterion_group!(
    benches,
    bench_encrypt,
    bench_encrypt_bytes_small,
    bench_encrypt_bytes_2000,
    bench_decrypt,
    bench_decrypt_string_small,
    bench_decrypt_string_2000
);
criterion_main!(benches);
