use trace::trace;

fn main() {
    env_logger::init();

    foo(Foo("Foo".to_string()));
}

#[derive(Debug)]
struct Foo(String);

#[trace(pretty)]
fn foo(a: Foo) -> Foo {
    a
}
