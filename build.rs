fn main() {
    tonic_build::configure()
        .build_server(true)
        .out_dir("src")
        .compile_protos(&["proto/zk_auth.proto"], &["proto/"])
        .unwrap()
}
