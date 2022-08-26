use trace::trace;

fn main() {
    env_logger::init();

    Foo::foo(1, 2);
    let _ = Foo::new().bar(1);
}

struct Foo;

#[trace(pretty, disable(new), prefix = "Foo::")]
impl Foo {
    fn new() -> Self {
        Self {}
    }

    #[trace(prefix_enter = "<static>::", a = "(defines velocity) {}", disable(b))]
    fn foo(a: u32, b: i32) -> i32 {
        b
    }

    #[trace(res = " {}")]
    fn bar(&self, a: i32) -> i32 {
        a
    }
}
