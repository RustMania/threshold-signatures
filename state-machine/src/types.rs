use std::fmt::{Debug, Error, Formatter};
use std::time::Duration;

pub trait StateMachineTraits {
    type InMsg;
    type OutMsg;
    type FinalState;
    type ErrorState;
}

#[derive(Debug)]
pub enum Transition<T>
where
    T: StateMachineTraits,
{
    NewState(BoxedState<T>),
    FinalState(Result<T::FinalState, T::ErrorState>),
}

// State has to be `Send` to be used with asynchronous channels,
// because it will be sent between thread in tokio pool.
pub type BoxedState<T> = Box<dyn State<T> + Send>;

impl<T> Debug for BoxedState<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "BoxedState")
    }
}

/// Special wrapper for an input of a state machine. Enables termination of the machine via sending a message to it
#[derive(Debug, Clone)]
pub enum Instruction<T> {
    Data(T),
    Terminate,
}

///   State interface
pub trait State<T>
where
    T: StateMachineTraits,
{
    fn start(&mut self) -> Option<Vec<T::OutMsg>>;
    fn is_message_expected(&self, msg: &T::InMsg, current_msg_set: &[T::InMsg]) -> bool;
    fn is_input_complete(&self, current_msg_set: &[T::InMsg]) -> bool;
    fn consume(&self, current_msg_set: Vec<T::InMsg>) -> Transition<T>;

    fn timeout(&self) -> Option<Duration> {
        None
    }
    fn timeout_outcome(
        &self,
        current_msg_set: Vec<T::InMsg>,
    ) -> Result<T::FinalState, T::ErrorState>;
}

/////////////////////////////////////////////////////////////////////////
