package tpm

// MaxKeyHandleLength is the length of the key handles RegisterKey returns:
// three lencode records ("TPM" separator and a length byte each) holding the
// TPM2B_PRIVATE buffer (integrity HMAC 2+32, IV 2+16, encrypted sensitive
// area 2+2+2+34+34 = 126 bytes for a P-256 key with SHA-256 name algorithm),
// the TPMT_PUBLIC area of the child template (88 bytes) and the 20-byte seed.
// These sizes follow from the TPM 2.0 structures, and match what a TPM
// returns (measured: 246).
const MaxKeyHandleLength = 3*(len("TPM")+1) + 126 + 88 + 20
