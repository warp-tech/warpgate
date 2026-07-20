macro_rules! check_conversation_id {
    ($actual:expr, $expected:expr) => {
        if $actual != $expected {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "Server sent invalid conversation id. Got {:?} but expected {:?}",
                    $actual, $expected
                ),
            ));
        }
    };
}

macro_rules! check_auth_scheme {
    ($actual:expr, $expected:expr) => {
        if $expected.is_none() {
            return Err(Error::new(ErrorKind::InvalidParameter, "auth scheme id is not set"));
        }

        if $actual != $expected.unwrap() {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                format!(
                    "Server sent invalid conversation id. Got {:?} but expected {:?}",
                    $actual,
                    $expected.unwrap()
                ),
            ));
        }
    };
}

macro_rules! check_sequence_number {
    ($actual:expr, $expected:expr) => {
        if $actual != $expected {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!(
                    "Server sent invalid sequence number. Got {:?} but expected {:?}",
                    $actual, $expected
                ),
            ));
        }
    };
}

#[macro_export]
macro_rules! check_if_empty {
    ($actual:expr, $msg:expr) => {
        $actual.ok_or_else(|| Error::new(ErrorKind::InternalError, $msg))?
    };
}
