pub mod zk_auth {
    include!("./zkp_auth.rs");
}
// get the user name to add maps in the server
use std::io::{stdin, Read};
// coming from the generated rs file using proto
use num_bigint::BigUint;
use zk_auth::{auth_client::AuthClient, AuthenticationChallengeRequest, RegisterRequest};
use ChaumPedersen::ZKP;
// async main
#[tokio::main]
async fn main() {
    // connet to the server
    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("Connection failed");
    println!("✅ Running the client");
    println!("Username: ");
    let mut username = String::new();
    stdin()
        .read_line(&mut username)
        .expect("user name is not specified");

    println!("Password: ");
    let mut secret = String::new();
    stdin()
        .read_line(&mut secret)
        .expect("password is not specified");

    // get constants
    let (a, b, p, q) = ZKP::get_constants();
    // generate y1, y2
    let request = RegisterRequest {
        user: username.clone().trim().to_string(),
        y1: ZKP::mod_exp(&a, &BigUint::from_bytes_be(&secret.trim().as_bytes()), &p).to_bytes_be(),
        y2: ZKP::mod_exp(&b, &BigUint::from_bytes_be(&secret.trim().as_bytes()), &p).to_bytes_be(),
    };
    let response = client.register(request).await.expect("Register failed");
    // println!("Response from server: {:?}", response);

    // lets generate r1 and r2
    let k = ZKP::gen_rand(&q);
    let r1 = ZKP::mod_exp(&a, &k, &p); //&BigUint::from_bytes_be(secret.trim().as_bytes())
    let r2 = ZKP::mod_exp(&b, &k, &p);

    let request = AuthenticationChallengeRequest {
        user: username.clone().trim().to_string(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };
    // println!("Request from client: {:?}", request);
    let challenge = client
        .create_authentication_challenge(request)
        .await
        .expect("Couldnt get a challenge from server");
    println!("Challenge response: {:?}", challenge);
}
