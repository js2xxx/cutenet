#[derive(Debug, PartialEq, Eq)]
pub struct Error<K, T: ?Sized> {
    pub kind: K,
    pub data: T,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    PacketTooShort,
    PacketTooLong,

    ProtocolUnknown,
    FormatInvalid,
    ChecksumInvalid,
    VersionInvalid,

    SrcInvalid,
    DstInvalid,
}
pub type ParseError<T: ?Sized> = Error<ParseErrorKind, T>;

impl ParseErrorKind {
    pub(crate) fn with<T>(self, data: T) -> ParseError<T> {
        ParseError { kind: self, data }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BuildErrorKind {
    HeadroomTooShort,
    PayloadTooLong,
}
pub type BuildError<T: ?Sized> = Error<BuildErrorKind, T>;

impl BuildErrorKind {
    pub(crate) fn with<T>(self, data: T) -> BuildError<T> {
        BuildError { kind: self, data }
    }
}
