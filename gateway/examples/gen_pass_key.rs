//! Generate a pass master key (RSA-2048 with safe primes; slow) as PEM on stdout.
use blind_rsa_signatures::pbrsa::PartiallyBlindKeyPairSha384PSSDeterministic;
use blind_rsa_signatures::DefaultRng;

fn main() {
    let t = std::time::Instant::now();
    let kp = PartiallyBlindKeyPairSha384PSSDeterministic::generate(&mut DefaultRng, 2048).unwrap();
    eprintln!("generated in {:?}", t.elapsed());
    print!("{}", kp.sk.to_pem().unwrap());
}
