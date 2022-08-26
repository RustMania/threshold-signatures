// error[E0658]: non-builtin inner attributes are unstable (see issue #54726)
// error[E0658]: The attribute `trace` is currently unknown to the compiler and may have meaning added to it in the future (see issue #29642)
//#![trace]

use trace::trace;

fn main() {
    env_logger::init();

    foo::foo();
    let foo = foo::Foo;
    foo.bar();
}

#[trace]
mod foo {
    pub(super) fn foo() {
        println!("I'm in foo!");
    }

    pub(super) struct Foo;
    impl Foo {
        pub(super) fn bar(&self) {}
    }
}
