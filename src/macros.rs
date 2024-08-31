macro_rules! log_parse {
    ($err:expr => $ret:expr) => {{
        #[cfg(feature = "log")]
        tracing::info!(
            "received malformed {}: {:?}",
            core::any::type_name_of_val(&$err.data),
            $err.kind
        );
        return $ret;
    }};
}

macro_rules! log_build {
    ($err:expr) => {
        #[cfg(feature = "log")]
        tracing::info!(
            "failed to build packet {}: {:?}",
            core::any::type_name_of_val(&$err.data),
            $err.kind
        )
    };
}

macro_rules! uncheck_build {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(err) => {
                log_build!(err);
                err.data
            }
        }
    };
}
