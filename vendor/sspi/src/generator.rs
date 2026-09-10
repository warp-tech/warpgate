use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use url::Url;

use crate::credssp::ServerError;
use crate::network_client::{AsyncNetworkClient, NetworkClient, NetworkProtocol};
use crate::{AcceptSecurityContextResult, Error, InitializeSecurityContextResult};

pub struct Interrupt<YieldTy, ResumeTy> {
    value_to_yield: Option<YieldTy>,
    yielded_value: YieldedValue<YieldTy>,
    resumed_value: ResumedValue<ResumeTy>,
    ready_to_resume: bool,
}

impl<YieldTy, ResumeTy> Future for Interrupt<YieldTy, ResumeTy>
where
    YieldTy: Unpin,
{
    type Output = ResumeTy;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.ready_to_resume {
            let resumed_value = this.resumed_value.try_lock().unwrap().take().unwrap();
            Poll::Ready(resumed_value)
        } else {
            let value_to_yield = this.value_to_yield.take().unwrap();
            *this.yielded_value.try_lock().unwrap() = Some(value_to_yield);
            this.ready_to_resume = true;
            Poll::Pending
        }
    }
}

#[derive(Debug)]
pub struct YieldPoint<YieldTy, ResumeTy> {
    yielded_value: YieldedValue<YieldTy>,
    resumed_value: ResumedValue<ResumeTy>,
}

impl<YieldTy, ResumeTy> Clone for YieldPoint<YieldTy, ResumeTy> {
    fn clone(&self) -> Self {
        Self {
            yielded_value: self.yielded_value.clone(),
            resumed_value: self.resumed_value.clone(),
        }
    }
}

impl<YieldTy, ResumeTy> YieldPoint<YieldTy, ResumeTy> {
    pub fn suspend(&mut self, value: YieldTy) -> Interrupt<YieldTy, ResumeTy> {
        Interrupt {
            value_to_yield: Some(value),
            yielded_value: Arc::clone(&self.yielded_value),
            resumed_value: Arc::clone(&self.resumed_value),
            ready_to_resume: false,
        }
    }
}

type YieldedValue<T> = Arc<Mutex<Option<T>>>;
type ResumedValue<T> = Arc<Mutex<Option<T>>>;
type PinnedFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub enum GeneratorState<YieldTy, OutTy> {
    Suspended(YieldTy),
    Completed(OutTy),
}

pub struct Generator<'a, YieldTy, ResumeTy, OutTy> {
    yielded_value: YieldedValue<YieldTy>,
    resumed_value: ResumedValue<ResumeTy>,
    generator: PinnedFuture<'a, OutTy>,
}

impl<'a, YieldTy, ResumeTy, OutTy> Generator<'a, YieldTy, ResumeTy, OutTy>
where
    OutTy: Send + 'a,
{
    pub fn new<Producer, Task>(producer: Producer) -> Self
    where
        Producer: FnOnce(YieldPoint<YieldTy, ResumeTy>) -> Task,
        Task: Future<Output = OutTy> + Send + 'a,
    {
        let yielded_value = Arc::new(Mutex::new(None));
        let resumed_value = Arc::new(Mutex::new(None));

        let yield_point = YieldPoint {
            yielded_value: Arc::clone(&yielded_value),
            resumed_value: Arc::clone(&resumed_value),
        };
        Self {
            yielded_value,
            resumed_value,
            generator: Box::pin(producer(yield_point)),
        }
    }

    pub fn start(&mut self) -> GeneratorState<YieldTy, OutTy> {
        self.step()
    }

    pub fn resume(&mut self, value: ResumeTy) -> GeneratorState<YieldTy, OutTy> {
        *self.resumed_value.try_lock().unwrap() = Some(value);
        self.step()
    }

    fn step(&mut self) -> GeneratorState<YieldTy, OutTy> {
        match execute_one_step(&mut self.generator) {
            None => {
                let value = self.yielded_value.try_lock().unwrap().take().unwrap();
                GeneratorState::Suspended(value)
            }
            Some(value) => GeneratorState::Completed(value),
        }
    }
}

fn execute_one_step<OutTy>(task: &mut PinnedFuture<'_, OutTy>) -> Option<OutTy> {
    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {
            // do nothing
        }
    }

    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);

    match task.as_mut().poll(&mut context) {
        Poll::Pending => None,
        Poll::Ready(item) => Some(item),
    }
}

/// Utility types and methods
impl<'a, YieldTy, ResumeTy, OutTy> Generator<'a, YieldTy, ResumeTy, Result<OutTy, Error>>
where
    OutTy: Send + 'a,
{
    pub fn resolve_to_result(&mut self) -> Result<OutTy, Error> {
        let state = self.start();
        match state {
            GeneratorState::Suspended(_) => Err(Error::new(
                crate::ErrorKind::UnsupportedFunction,
                "cannot finish generator",
            )),
            GeneratorState::Completed(res) => res,
        }
    }

    pub fn unwrap(&mut self) -> OutTy {
        self.resolve_to_result().unwrap()
    }

    pub fn expect(&mut self, msg: &str) -> OutTy {
        self.resolve_to_result().expect(msg)
    }
}

impl<'a, YieldTy, ResumeTy, OutTy> Generator<'a, YieldTy, ResumeTy, Result<OutTy, ServerError>>
where
    OutTy: Send + 'a,
{
    pub fn resolve_to_result(&mut self) -> Result<OutTy, ServerError> {
        let state = self.start();
        match state {
            GeneratorState::Suspended(_) => Err(ServerError {
                ts_request: None,
                error: Error::new(crate::ErrorKind::UnsupportedFunction, "cannot finish generator"),
            }),
            GeneratorState::Completed(res) => res,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkRequest {
    pub protocol: NetworkProtocol,
    pub url: Url,
    pub data: Vec<u8>, // avoid life time problem, suspend requires 'static life time
}

impl<YieldTy, ResumeTy, OutTy> std::fmt::Debug for Generator<'_, YieldTy, ResumeTy, OutTy>
where
    YieldTy: std::fmt::Debug,
    ResumeTy: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Generator")
            .field("yielded_value", &self.yielded_value)
            .field("resumed_value", &self.resumed_value)
            .finish()
    }
}

pub type GeneratorInitSecurityContext<'a> =
    Generator<'a, NetworkRequest, crate::Result<Vec<u8>>, crate::Result<InitializeSecurityContextResult>>;

pub type GeneratorAcceptSecurityContext<'a> =
    Generator<'a, NetworkRequest, crate::Result<Vec<u8>>, crate::Result<AcceptSecurityContextResult>>;

pub type GeneratorChangePassword<'a> = Generator<'a, NetworkRequest, crate::Result<Vec<u8>>, crate::Result<()>>;

pub(crate) type YieldPointLocal = YieldPoint<NetworkRequest, crate::Result<Vec<u8>>>;

impl<'a, YieldType, ResumeType, OutType, ErrorType> From<Result<OutType, ErrorType>>
    for Generator<'a, YieldType, ResumeType, Result<OutType, ErrorType>>
where
    OutType: Send + 'a,
    ErrorType: Send + 'a,
{
    fn from(value: Result<OutType, ErrorType>) -> Self {
        Generator::new(move |_| async move { value })
    }
}

/// Utilities for working with network client
impl<'a, OutTy> Generator<'a, NetworkRequest, crate::Result<Vec<u8>>, OutTy>
where
    OutTy: 'a + Send,
{
    #[cfg(feature = "network_client")]
    pub fn resolve_with_default_network_client(&mut self) -> OutTy {
        let network_client = crate::network_client::reqwest_network_client::ReqwestNetworkClient;
        self.resolve_with_client(&network_client)
    }

    pub fn resolve_with_client(&mut self, network_client: &dyn NetworkClient) -> OutTy {
        let mut state = self.start();
        loop {
            match state {
                GeneratorState::Suspended(ref request) => {
                    state = self.resume(NetworkClient::send(network_client, request));
                }
                GeneratorState::Completed(res) => {
                    return res;
                }
            }
        }
    }

    pub async fn resolve_with_async_client(&mut self, network_client: &mut dyn AsyncNetworkClient) -> OutTy {
        let mut state = self.start();

        loop {
            match state {
                GeneratorState::Suspended(ref request) => {
                    state = self.resume(network_client.send(request).await);
                }
                GeneratorState::Completed(client_state) => {
                    return client_state;
                }
            }
        }
    }
}
