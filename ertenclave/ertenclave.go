// Package ertenclave provides functionality for Go enclaves like remote attestation and sealing.
package ertenclave

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// #include <openenclave/enclave.h>
import "C"

import (
	"errors"
	"unsafe"

	"github.com/edgelesssys/ertgolib/ert"
)

// GetRemoteReport gets a report signed by the enclave platform for use in remote attestation.
//
// The report shall contain the data given by the reportData parameter.
func GetRemoteReport(reportData []byte) ([]byte, error) {
	var report *C.uint8_t
	var reportSize C.size_t

	res := C.oe_get_report_v2(
		C.OE_REPORT_FLAGS_REMOTE_ATTESTATION,
		(*C.uint8_t)(&reportData[0]), C.size_t(len(reportData)),
		nil, 0,
		&report, &reportSize)

	if res != C.OE_OK {
		return nil, oeError(res)
	}

	result := C.GoBytes(unsafe.Pointer(report), C.int(reportSize))
	C.oe_free_report(report)
	return result, nil
}

// VerifyRemoteReport verifies the integrity of the remote report and its signature.
//
// This function verifies that the report signature is valid. It
// verifies that the signing authority is rooted to a trusted authority
// such as the enclave platform manufacturer.
//
// Returns the parsed report if the signature is valid.
// Returns an error if the signature is invalid.
func VerifyRemoteReport(reportBytes []byte) (ert.Report, error) {
	var report C.oe_report_t

	res := C.oe_verify_report(
		(*C.uint8_t)(&reportBytes[0]), C.size_t(len(reportBytes)),
		&report)

	if res != C.OE_OK {
		return ert.Report{}, oeError(res)
	}

	if (report.identity.attributes & C.OE_REPORT_ATTRIBUTES_REMOTE) == 0 {
		return ert.Report{}, oeError(C.OE_UNSUPPORTED)
	}

	return ert.Report{
		Data:            C.GoBytes(unsafe.Pointer(report.report_data), C.int(report.report_data_size)),
		SecurityVersion: uint(report.identity.security_version),
		Debug:           (report.identity.attributes & C.OE_REPORT_ATTRIBUTES_DEBUG) != 0,
		UniqueID:        C.GoBytes(unsafe.Pointer(&report.identity.unique_id[0]), C.OE_UNIQUE_ID_SIZE),
		SignerID:        C.GoBytes(unsafe.Pointer(&report.identity.signer_id[0]), C.OE_SIGNER_ID_SIZE),
		ProductID:       C.GoBytes(unsafe.Pointer(&report.identity.product_id[0]), C.OE_PRODUCT_ID_SIZE),
	}, nil
}

// GetUniqueSealKey gets a key derived from a measurement of the enclave.
//
// keyInfo can be used to retrieve the same key later, on a newer security version.
func GetUniqueSealKey() (key, keyInfo []byte, err error) {
	return getSealKeyByPolicy(C.OE_SEAL_POLICY_UNIQUE)
}

// GetProductSealKey gets a key derived from the signer and product id of the enclave.
//
// keyInfo can be used to retrieve the same key later, on a newer security version.
func GetProductSealKey() (key, keyInfo []byte, err error) {
	return getSealKeyByPolicy(C.OE_SEAL_POLICY_PRODUCT)
}

// GetSealKey gets a key from the enclave platform using existing key information.
func GetSealKey(keyInfo []byte) ([]byte, error) {
	var keyBuffer *C.uint8_t
	var keySize C.size_t
	if res := C.oe_get_seal_key_v2((*C.uint8_t)(&keyInfo[0]), C.size_t(len(keyInfo)), &keyBuffer, &keySize); res != C.OE_OK {
		return nil, oeError(res)
	}

	key := C.GoBytes(unsafe.Pointer(keyBuffer), C.int(keySize))
	C.oe_free_seal_key(keyBuffer, nil)
	return key, nil
}

func getSealKeyByPolicy(sealPolicy C.oe_seal_policy_t) (key, keyInfo []byte, err error) {
	var keyBuffer, keyInfoBuffer *C.uint8_t
	var keySize, keyInfoSize C.size_t
	if res := C.oe_get_seal_key_by_policy_v2(sealPolicy, &keyBuffer, &keySize, &keyInfoBuffer, &keyInfoSize); res != C.OE_OK {
		return nil, nil, oeError(res)
	}

	key = C.GoBytes(unsafe.Pointer(keyBuffer), C.int(keySize))
	keyInfo = C.GoBytes(unsafe.Pointer(keyInfoBuffer), C.int(keyInfoSize))
	C.oe_free_seal_key(keyBuffer, keyInfoBuffer)
	return
}

func oeError(res C.oe_result_t) error {
	return errors.New(C.GoString(C.oe_result_str(res)))
}
