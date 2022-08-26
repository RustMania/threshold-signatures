use trace::trace;

fn main() {
    env_logger::init();

    foo(1);
}

#[trace(pause)]
fn foo(a: i32) -> i32 {
    a
}
