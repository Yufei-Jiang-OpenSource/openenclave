/*++

Copyright (c) 2014  Microsoft Corporation

Module Name:

    vbsvmcrypto.h

Abstract:

    Contains type definitions used by the crypto and attesation in VBS VM.

Author:

    Jingbo Wu (jingbowu) 17-April-2018 - Created

Revision History:

--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push)
#pragma pack(1)

//
// Hashing algorithm ID to use for SK Secure Signing using IDK_S
// The value used is CALG_SHA_256 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256).
// (Copied from VSM_SK_SECURE_SIGNING_HASH_ALG_SHA_256)
//
#define SVC_VSM_SK_SECURE_SIGNING_HASH_ALG_SHA_256 (32780)

#define VBS_VM_REPORT_PKG_HEADER_VERSION_CURRENT (1)
#define VBS_VM_REPORT_SIGNATURE_SCHEME_SHA256_RSA_PSS_SHA256 (1)

//
// VBS Report package header
//

typedef struct VBS_VM_REPORT_PKG_HEADER
{
    UINT32 PackageSize;
    UINT32 Version;
    UINT32 SignatureScheme;
    UINT32 SignatureSize;
    UINT32 Reserved;

} VBS_VM_REPORT_PKG_HEADER;

//
// VBS Report body
//

#define VBS_VM_REPORT_VERSION_CURRENT (1)

#define VBS_VM_REPORT_DATA_LENGTH     (64)
#define VBS_VM_LENGTH_16  (16)
#define VBS_VM_SHA256_SIZE   (32)

typedef struct _VBS_VM_IDENTITY
{
    //
    // Owner ID is the runtime ID assigned to VBS VM when the instance is created.
    // It is an input parameter when VM is created.
    //
    UINT8 OwnerId[VBS_VM_SHA256_SIZE];

    //
    // Measurement is the hash of VBS VM (memory pages, VP, page tables etc.).
    //
    UINT8 Measurement[VBS_VM_SHA256_SIZE];

    //
    // The value of the signer measurement (SHA256 of Signer RSA key pub).
    // V1 VBS VM only supports Windows signed binaries.
    //
    UINT8 Signer[VBS_VM_SHA256_SIZE];

    UINT8 Reserved1[32];

    //
    // SVN of VBS VM platform isolation support, which including SK extention and
    // hypervisor to support VM isolation.
    //
    UINT32 PlatfromIsolationSvn;

    //
    // SVN of secure kernel.
    //
    UINT32 SecureKernelSvn;

    //
    // SVN of VBS platform boot chain.
    //
    UINT32 PlatformBootChainSvn;

    //
    // The guest VTL level that CreateReport called from.
    //
    UINT32 GuestVtl;

    UINT8 Reserved2[32];

} VBS_VM_IDENTITY;

#define VBS_VM_FLAG_DEBUG_ENABLED         (0x00000001)

//
// VBS VM Module description.
//
typedef struct _VBS_VM_MODULE
{
    UINT8 ImageHash[VBS_VM_SHA256_SIZE];

    //
    // The value of the signer measurement (SHA256 of Signer RSA key pub).
    // V1 VBS VM supports sigStruct signing rather than individual image signing.
    //
    UINT8 Signer[VBS_VM_SHA256_SIZE];

    //
    // User configured data when image is compiled. {ImageId, FamilyId} represents product ID.
    //
    UINT8 FamilyId[VBS_VM_LENGTH_16];
    UINT8 ImageId[VBS_VM_LENGTH_16];

    //
    // VBS VM security attributes that describe the runtime policy. For example, debug policy.
    //
    UINT32 Attributes;

    //
    // VBS VM module security version.
    //
    UINT32 Svn;

    //
    // The VTL where the root module runs.
    //
    UINT32 Vtl;

    UINT8 Reserved[32];

} VBS_VM_MODULE;

#define VBS_VM_NUMBER_OF_MODULES  2
#define VBS_VM_MAX_SIGNATURE_SIZE 256
typedef struct _VBS_VM_REPORT
{
    VBS_VM_REPORT_PKG_HEADER Header;

    UINT32 Version;

    UINT8 ReportData[VBS_VM_REPORT_DATA_LENGTH];

    // The identity conatins the module information and VBS platform security
    // properties.
    VBS_VM_IDENTITY Identity;

    VBS_VM_MODULE Modules[VBS_VM_NUMBER_OF_MODULES];
    UINT8 Signature[VBS_VM_MAX_SIGNATURE_SIZE];

} VBS_VM_REPORT;

//
// AMD SEV-SNP Report (per spec).
//
typedef struct _SNP_SIGNATURE
{
    UINT8 RComponent[72];
    UINT8 SComponent[72];
    UINT8 RSVD[368];
} SNP_SIGNATURE;

#define SNP_REPORT_DATA_LENGTH (64)
typedef struct _SNP_VM_REPORT
{
    UINT32 SnpVersion;
    UINT32 SnpGuestSvn;
    UINT64 SnpPolicy;
    UINT8  SnpFamilyId[16];
    UINT8  SnpImageId[16];
    UINT32 SnpVMPL;
    UINT32 SnpSignatureAlgo;
    UINT64 SnpTcbVersion;
    UINT64 SnpPlatformInfo;
    UINT32 SnpReportFlags;
    UINT32 SnpReserved;
    // Payload includes 512 bits of user data,
    // which is used to carry a SHA256 hash of a larger buffer
    UINT8  SnpReportData[SNP_REPORT_DATA_LENGTH];
    UINT8  SnpMeasurement[48];
    UINT8  SnpHostdata[32];
    UINT8  SnpIdKeyDigest[48];
    UINT8  SnpAuthorKeyDigest[48];
    UINT8  SnpReportId[32];
    UINT8  SnpReportIdMa[32];
    SNP_SIGNATURE  SnpSignature;
} SNP_VM_REPORT;

//
// Union of different signed isolation reports.
//
typedef struct _HW_ATTESTATION
{
    union
    {
        SNP_VM_REPORT SnpReport; // SnpReportData holds hash of HclData
        VBS_VM_REPORT VbsReport; // ReportData holds hash of HclData
    } Report;
} HW_ATTESTATION;

//
// Extended data the HCL will provided, hashed in signed report.
//

// Report Type
typedef enum _IGVM_REPORT_TYPE
{
    InvalidReport = 0,
    VbsVmReport,
    SnpVmReport
} IGVM_REPORT_TYPE, *PIGVM_REPORT_TYPE;

// Request type
typedef enum _IGVM_REQUEST_TYPE
{
    InvalidRequest = 0,
    KeyReleaseRequest,
    EkCertRequest
} IGVM_REQUEST_TYPE, *PIGVM_REQUEST_TYPE;

#define IGVM_ATTEST_VERSION_CURRENT  (1)

//
// User data, used for host attestation requests.
//
typedef struct _IGVM_REQUEST_DATA
{
    // Overall size of payload.
    UINT32 DataSize;

    // The type of isolation that generated this report.
    IGVM_REPORT_TYPE ReportType;

    // The type of request.
    IGVM_REQUEST_TYPE RequestType;

    // Version of this structure, currently IGVM_ATTEST_VERSION_CURRENT (1).
    UINT32 Version;

    // Size of data blob.
    UINT32 KeyDataSize;

    // Data holds EkPub or Transport Key.
    UINT8 KeyData[];
} IGVM_REQUEST_DATA;

#define ATTESTATION_MAGIC 0x414C4348 // HCLA
#define ATTESTATION_VERSION (1)

//
// Unmeasured data used to provide transport sanity and versioning.
//
typedef struct _ATTESTATION_HEADER
{
    UINT32 Magic;
    UINT32 Version;
    UINT32 ReportSize;
    UINT32 Reserved;
} ATTESTATION_HEADER;

//
// Attestation report delivered to host attestation agent.
//
typedef struct _ATTESTATION_REPORT
{
    ATTESTATION_HEADER Header; // Not measured
    HW_ATTESTATION HwReport; // Signed report
    IGVM_REQUEST_DATA HclData; // HCL sourced data
} ATTESTATION_REPORT;


#define VBS_VM_AES_GCM_KEY_LENGTH 32

//
// Attestation response structures.
//

//
// Definitions for key release request.
//
#define IGVM_KEY_MESSAGE_HEADER_VERSION_1 (1)

_Struct_size_bytes_(DataSize)
typedef struct _IGVM_KEY_MESSAGE_HEADER
{
    UINT32 DataSize;
    UINT32 Version;
    UINT32 EncryptedTransportKeyOffset;
    UINT32 EncryptedTransportKeyLength;
    UINT32 EncryptedKeyArrayOffset;
    UINT32 EncryptedKeyArrayLength;
    UINT8 Payload[];
} IGVM_KEY_MESSAGE_HEADER;


//
// Definitions for certificate request.
//

#define IGVM_CERT_MESSAGE_HEADER_VERSION_1 (1)

_Struct_size_bytes_(DataSize)
typedef struct _IGVM_CERT_MESSAGE_HEADER
{
    UINT32 DataSize;
    UINT32 Version;
    UINT32 SubjectCertOffset;
    UINT32 SubjectCertLength;
    UINT32 CaCertOffset;
    UINT32 CaCertLength;
    UINT8 Payload[];

} IGVM_CERT_MESSAGE_HEADER;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif