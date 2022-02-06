use thrussh::ChannelId;

pub struct Client {
    id: u64,
    shell_channel: Option<ChannelId>,
    handle: thrussh::server::Handle,
}

impl Client {
    fn new(handle: thrussh::server::Handle) -> Self {
        Self {
            id: 0,
            shell_channel: None,
            handle,
        }
    }
}
