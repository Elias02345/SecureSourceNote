fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match ssn_cli::run(&args, &ssn_cli::home()) {
        Ok(out) => {
            if !out.is_empty() {
                println!("{out}");
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}
