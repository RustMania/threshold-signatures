trace
-----

A procedural macro for tracing the execution of functions.
Adding `#[trace]` to the top of any function will insert `log::trace!` statements at the beginning, and the end of that function, notifying you of when that function was entered and exited and printing the argument and return values.
This is useful for quickly debugging whether functions that are supposed to be called are actually called without manually inserting print statements.

Hierarchical invocations of trace will be combined with the innermost taking precedence over the item it was invoked on,
for example, tracing can be enabled on the level of implementation and fine-tuned on the level of specific methods.  

## Installation

Add `trace = "*"`, `log = "*"`, and `env_logger = "*"` to your `Cargo.toml`.

## Example

Here is an example you can find in the examples' folder. If you've cloned the project, you can run this with `cargo run --example example_combine`.

```rust
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
```

Output:
```
[2020-06-16T08:18:42Z TRACE example_combine] >>> Foo::<static>::foo
	a: (defines velocity) 1
	...
[2020-06-16T08:18:42Z TRACE example_combine] <<< Foo::foo
	res: 2
[2020-06-16T08:18:42Z TRACE example_combine] >>> Foo::bar
	a: 1
[2020-06-16T08:18:42Z TRACE example_combine] <<< Foo::bar
	res:  1
```

## Optional Arguments

Trace takes a few optional arguments, described below:

#### Prefixes
- `prefix` -
  The prefix of the `log::trace!` statement when a function is entered and exited.

- `prefix_enter` -
  The prefix of the `log::trace!` statement when a function is entered.

- `prefix_exit` -
  The prefix of the `println!` statement when a function is exited.
  
  Option `prefix` is mutually exclusive with `prefix_enter`\\`prefix_exit` if used within the same macro invocation.
  
  Prefixes are combined for hierarchical invocation of the macro, see example above. 

#### Output control
- `enable` -
  When applied to a `mod` or `impl`, `enable` takes a list of function names to print, not printing any functions that are not part of this list.
  All functions are enabled by default.
  When applied to an `impl` method or a function, `enable` takes a list of arguments to print, not printing any arguments that are not part of the list.
  All arguments are enabled by default.

- `disable` -
  When applied to a `mod` or `impl`, `disable` takes a list of function names to not print, printing all other functions in the `mod` or `impl`.
  No functions are disabled by default.
  When applied to an `impl` method or a function, `disable` takes a list of arguments to not print, printing all other arguments.
  No arguments are disabled by default.
  
- `<name> = <formatting>` -
  If function accepts a parameter with the specified name `<name>`, then `<formatting>` will be used for the parameter, see example above, `fn foo(...)`.
  Only applies to function calls, and in all other cases is ignored. 

- `pretty`
  All parameters to be printed and which have no specific formatting are printed with `{:#?}`. This option propagates across hierarchical macro invocations. 
  
  Options `enable` and `disable` are mutually exclusive within the same macro invocation.
  If they are applied to function parameters, the relevant parameters must implement the `Debug` trait.
  If some parameters are omitted, a hint `...` will be printed out to indicate that the output does not contain all passed arguments. 


#### Flow control
- `pause` -
  When given as an argument to `#[trace]`, execution is paused after each line of tracing output until enter is pressed.
  This allows you to trace through a program step by step.


All of these options are covered in the `examples` folder.
