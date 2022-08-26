use std::cmp::max;
use trace::trace;

#[tokio::main]
async fn main() {
    env_logger::init();

    println!("future max = {}", future_max(1, 2).await);

    let mut bar = Bar::new();
    bar.set(2).await;
    println!("Bar({})", bar.0);
}

#[trace]
async fn future_max(a: u64, b: u64) -> u64 {
    let a = async { a };
    let b = async { b };
    max(a.await, b.await)
}

struct Bar(u32);

#[trace(disable(new))]
impl Bar {
    fn new() -> Self {
        Self(0)
    }

    async fn set(&mut self, a: u32) {
        self.0 = async { a }.await;
    }
}
