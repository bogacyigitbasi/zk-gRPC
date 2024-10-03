use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use tonic::{transport::Server, Code, Request, Response, Status};
use ChaumPedersen::ZKP;

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
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, User>>,
    pub auth_id_user: Mutex<HashMap<String, String>>,
}

// tonic async trait for async
#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        // we need to generate y1 and y2 and user info (likely id)
        let request = request.into_inner();

        // let mut user = User::default();
        let user_name = request.user;

        println!("Processing  Register, {}", user_name);

        let y1 = BigUint::from_bytes_be(&request.y1);
        let y2 = BigUint::from_bytes_be(&request.y2);

        let mut user = User::default();

        user.name = user_name.clone();
        user.y1 = y1;
        user.y2 = y2;

        let mut user_map = &mut self.user_info.lock().unwrap();
        user_map.insert(user_name.clone(), user);
        // let test_user = user_map.get_mut(&user_name);
        println!("map , {:?}", &user_map);
        // println!("Register successful for , {}", user_name);
        Ok((Response::new(RegisterResponse {})))
    }

    ///
    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        // println!("Challenge is being generated, {:?}", request);
        // we need to generate r1 and r2
        let request = request.into_inner();

        let user_map = &mut self.user_info.lock().unwrap();

        let user_name = request.user.trim().to_string();
        // println!("Challenge is being generated, {}", &user_name);

        println!("map {:?}", &user_map);

        // let mut test_user = user_map.get_mut(&user_name);
        // println!("Challenge is being generated, {:?}", test_user);
        if let Some(user_info) = user_map.get_mut(&user_name) {
            // if (test_user.is_some()) {
            // let mut user_info = test_user.unwrap();
            user_info.r1 = BigUint::from_bytes_be(&request.r1);
            user_info.r2 = BigUint::from_bytes_be(&request.r2);

            let (_, q, _, _) = ZKP::get_constants();
            // got the order, lets call max rand for challenge
            // let c = BigUint::from(123u32);
            let c = ZKP::gen_rand(&q);
            user_info.c = c.clone();
            let auth_id = ZKP::gen_rand_string(12);

            let mut auth_id_user = &mut self.auth_id_user.lock().unwrap();

            auth_id_user.insert(auth_id.clone(), user_name.clone());
            println!("✅ Successful Challenge Request username: {:?}", user_name);
            Ok(Response::new(AuthenticationChallengeResponse {
                auth_id: auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("User {} not found in db", user_name),
            ))
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        println!("Verification request, {:?}", request);
        // we need to generate r1 and r2
        let request = request.into_inner();

        let mut user_map = &mut self.auth_id_user.lock().unwrap();
        let mut user_sign_map = &mut self.user_info.lock().unwrap();

        let auth_id = request.auth_id;

        let instance = user_sign_map.get(&auth_id).unwrap();

        if let Some(auth_id) = user_map.get_mut(&auth_id) {
            let (a, b, p, q) = ZKP::get_constants();
            let zkp = ZKP::init(&a, &b, &p, &q);
            let verif = zkp.verify(
                &instance.y1,
                &instance.y2,
                &instance.r1,
                &instance.r2,
                &instance.c,
                &instance.s,
            );
            if (verif) {
                Ok(Response::new(AuthenticationAnswerResponse {
                    session_id: ZKP::gen_rand_string(12),
                }))
            } else {
                Err(Status::new(
                    Code::PermissionDenied,
                    format!("Verification failed"),
                ))
            }
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("AuthId: {} not found in database", auth_id),
            ))
        }
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
