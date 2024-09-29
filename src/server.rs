use tonic::{transport::Server, Code, Request, Response, Status};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use zkp_auth::auth_server;

fn main() {
    println!("Hey this is server. ");
}

// tokio struct is defined
// now we need to implement the traits specified in the protobuf file
#[derive(Debug, Default)]
struct AuthImpl {}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:500051".to_string();
    println!("√ Running the serer in {}, ", addr);
}
