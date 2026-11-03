use std::process;

fn main() {
    let exit_code = match dotler::cli::run(None) {
        Ok(code) => code,
        Err(err) => err.exit_code(),
    };
    process::exit(exit_code);
}
