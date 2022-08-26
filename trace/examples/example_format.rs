use trace::trace;

fn main() {
    env_logger::init();

    foo(1, 2);
}

#[trace(a = "received {:?}")]
fn foo(a: i32, b: i32) {
    println!("I'm in foo!");
    bar((a, b));
}

#[trace(res = "returning {:?}", disable(b))]
fn bar((a, b): (i32, i32)) -> i32 {
    println!("I'm in bar!");
    if a == 1 {
        2
    } else {
        b
    }
}
