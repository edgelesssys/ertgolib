#define OE_UNIQUE_ID_SIZE 32
#define OE_SIGNER_ID_SIZE 32
#define OE_PRODUCT_ID_SIZE 16
#define OE_REPORT_ATTRIBUTES_DEBUG 1

typedef enum _oe_enclave_type
{
    /**
     * OE_ENCLAVE_TYPE_AUTO will pick the type
     * based on the target platform that is being built, such that x64 binaries
     * will use SGX.
     */
    OE_ENCLAVE_TYPE_AUTO = 1,
    /**
     * OE_ENCLAVE_TYPE_SGX will force the platform to use SGX, but any platform
     * other than x64 will not support this and will generate errors.
     */
    OE_ENCLAVE_TYPE_SGX = 2,
    /**
     * OE_ENCLAVE_TYPE_OPTEE will force the platform to use OP-TEE, but any
     * platform other than one that implements ARM TrustZone with OP-TEE as its
     * secure kernel will not support this and will generate errors.
     */
    OE_ENCLAVE_TYPE_OPTEE = 3,
    /**
     * Unused
     */
    __OE_ENCLAVE_TYPE_MAX = 0xffffffff,
} oe_enclave_type_t;

typedef struct _oe_identity
{
    /** Version of the oe_identity_t structure */
    uint32_t id_version;

    /** Security version of the enclave. For SGX enclaves, this is the
     *  ISVN value */
    uint32_t security_version;

    /** Values of the attributes flags for the enclave -
     *  OE_REPORT_ATTRIBUTES_DEBUG: The report is for a debug enclave.
     *  OE_REPORT_ATTRIBUTES_REMOTE: The report can be used for remote
     *  attestation */
    uint64_t attributes;

    /** The unique ID for the enclave.
     * For SGX enclaves, this is the MRENCLAVE value */
    uint8_t unique_id[OE_UNIQUE_ID_SIZE];

    /** The signer ID for the enclave.
     * For SGX enclaves, this is the MRSIGNER value */
    uint8_t signer_id[OE_SIGNER_ID_SIZE];

    /** The Product ID for the enclave.
     * For SGX enclaves, this is the ISVPRODID value. */
    uint8_t product_id[OE_PRODUCT_ID_SIZE];
} oe_identity_t;

typedef struct _oe_report
{
    /** Size of the oe_report_t structure. */
    size_t size;

    /** The enclave type. Currently always OE_ENCLAVE_TYPE_SGX. */
    oe_enclave_type_t type;

    /** Size of report_data */
    size_t report_data_size;

    /** Size of enclave_report */
    size_t enclave_report_size;

    /** Pointer to report data field within the report byte-stream supplied to
     * oe_parse_report */
    uint8_t *report_data;

    /** Pointer to report body field within the report byte-stream supplied to
     * oe_parse_report. */
    uint8_t *enclave_report;

    /** Contains the IDs and attributes that are part of oe_identity_t */
    oe_identity_t identity;
} oe_report_t;