#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
cutenet_error::make_error!(ParseErrorKind => pub ParseError);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BuildErrorKind {
    HeadroomTooShort,
    PayloadTooLong,
}
cutenet_error::make_error!(BuildErrorKind => pub BuildError);
