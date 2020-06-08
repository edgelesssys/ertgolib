package ert

// Report is a parsed enclave report.
type Report struct {
	Data            []byte // The report data that has been included in the report.
	SecurityVersion uint   // Security version of the enclave. For SGX enclaves, this is the ISVN value.
	Debug           bool   // If true, the report is for a debug enclave.
	UniqueID        []byte // The unique ID for the enclave. For SGX enclaves, this is the MRENCLAVE value.
	SignerID        []byte // The signer ID for the enclave. For SGX enclaves, this is the MRSIGNER value.
	ProductID       []byte // The Product ID for the enclave. For SGX enclaves, this is the ISVPRODID value.
}
