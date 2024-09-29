use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
    AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
};

#[derive(Debug, Default)]
pub struct User {
    // register
    pub name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // auth
    pub r1: BigUint,
    pub r2: BigUint,
    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

// tokio struct is defined
// now we need to implement the traits specified in the protobuf file
#[derive(Debug, Default)]
struct AuthImpl {}

// tonic async trait for async
#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        // we need to generate y1 and y2 and user info (likely id)
        let request = request.into_inner();

        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut user = User::default();
        user.name = request.user;
        user.y1 = y1;
        user.y2 = y2;

        Ok((Response::new(RegisterResponse {})))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        todo!()
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        todo!()
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    // emojis commad + ctrl + space :p
    println!("✅ Running the serer in {}, ", addr);

    let auth = AuthImpl::default();
    Server::builder()
        .add_service(AuthServer::new(auth))
        .serve(addr.parse().expect("could not convert address"))
        .await
        .unwrap();
}
