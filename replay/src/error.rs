use crate::metadata::ReplayMetadata;

#[derive(Debug, Eq, PartialEq)]
pub enum ReplayError {
    MetadataFileNotFound,
    CantDeriveMetadataFile,
    PayloadFileNotFound,
    InvalidMetadataFile,
    InvalidPayloadFile,
    InvalidCache,
    NotReproducible,
    NotMinimizable,
    KernelNotFound,
    ImageNotFound,
    DifferentCrash(ReplayMetadata),
}
