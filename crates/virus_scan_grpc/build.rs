fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .compile_protos(
            &[
                "src/proto/virus_scan.proto",
                "src/proto/vuln_scan.proto",
                "src/proto/lynis_scan.proto",
            ],
            &["src/proto"],
        )
        .unwrap();
    Ok(())
}
