import Foundation

struct KeyChainAccessor {
  static func get(service: String, key: String) throws -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let error = OSStatusError(rawValue: SecItemCopyMatching(query as CFDictionary, &item))
    switch error {
    case .secSuccess:
      if let item = item as? Data {
        return item
      } else {
        fatalError()
      }
    case .secItemNotFound:
      return nil
    default:
      throw error
    }
  }

  static func set(service: String, key: String, data: Data) throws {
    _ = try delete(service: service, key: key)

    let access = SecAccessControlCreateWithFlags(
      nil,
      kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
      .userPresence,
      nil
    )
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccessControl as String: access as Any,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
      kSecValueData as String: data,
    ]
    let error = OSStatusError(rawValue: SecItemAdd(query as CFDictionary, nil))
    if error != .secSuccess { throw error }
  }

  static func delete(service: String, key: String) throws -> Bool {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
    let error = OSStatusError(rawValue: SecItemDelete(query as CFDictionary))
    switch error {
    case .secSuccess:
      return true
    case .secItemNotFound:
      return false
    default:
      throw error
    }
  }
}

enum OSStatusError: Error, LocalizedError {
  case secSuccess
  case secUnimplemented
  case secDiskFull
  case secIO
  case secOpWr
  case secParam
  case secWrPerm
  case secAllocate
  case secUserCanceled
  case secBadReq
  case secInternalComponent
  case secCoreFoundationUnknown
  case secMissingEntitlement
  case secRestrictedAPI
  case secNotAvailable
  case secReadOnly
  case secAuthFailed
  case secNoSuchKeychain
  case secInvalidKeychain
  case secDuplicateKeychain
  case secDuplicateCallback
  case secInvalidCallback
  case secDuplicateItem
  case secItemNotFound
  case secBufferTooSmall
  case secDataTooLarge
  case secNoSuchAttr
  case secInvalidItemRef
  case secInvalidSearchRef
  case secNoSuchClass
  case secNoDefaultKeychain
  case secInteractionNotAllowed
  case secReadOnlyAttr
  case secWrongSecVersion
  case secKeySizeNotAllowed
  case secNoStorageModule
  case secNoCertificateModule
  case secNoPolicyModule
  case secInteractionRequired
  case secDataNotAvailable
  case secDataNotModifiable
  case secCreateChainFailed
  case secInvalidPrefsDomain
  case secInDarkWake
  case secACLNotSimple
  case secPolicyNotFound
  case secInvalidTrustSetting
  case secNoAccessForItem
  case secInvalidOwnerEdit
  case secTrustNotAvailable
  case secUnsupportedFormat
  case secUnknownFormat
  case secKeyIsSensitive
  case secMultiplePrivKeys
  case secPassphraseRequired
  case secInvalidPasswordRef
  case secInvalidTrustSettings
  case secNoTrustSettings
  case secPkcs12VerifyFailure
  case secNotSigner
  case secDecode
  case secServiceNotAvailable
  case secInsufficientClientID
  case secDeviceReset
  case secDeviceFailed
  case secAppleAddAppACLSubject
  case secApplePublicKeyIncomplete
  case secAppleSignatureMismatch
  case secAppleInvalidKeyStartDate
  case secAppleInvalidKeyEndDate
  case secConversionError
  case secAppleSSLv2Rollback
  case secQuotaExceeded
  case secFileTooBig
  case secInvalidDatabaseBlob
  case secInvalidKeyBlob
  case secIncompatibleDatabaseBlob
  case secIncompatibleKeyBlob
  case secHostNameMismatch
  case secUnknownCriticalExtensionFlag
  case secNoBasicConstraints
  case secNoBasicConstraintsCA
  case secInvalidAuthorityKeyID
  case secInvalidSubjectKeyID
  case secInvalidKeyUsageForPolicy
  case secInvalidExtendedKeyUsage
  case secInvalidIDLinkage
  case secPathLengthConstraintExceeded
  case secInvalidRoot
  case secCRLExpired
  case secCRLNotValidYet
  case secCRLNotFound
  case secCRLServerDown
  case secCRLBadURI
  case secUnknownCertExtension
  case secUnknownCRLExtension
  case secCRLNotTrusted
  case secCRLPolicyFailed
  case secIDPFailure
  case secSMIMEEmailAddressesNotFound
  case secSMIMEBadExtendedKeyUsage
  case secSMIMEBadKeyUsage
  case secSMIMEKeyUsageNotCritical
  case secSMIMENoEmailAddress
  case secSMIMESubjAltNameNotCritical
  case secSSLBadExtendedKeyUsage
  case secOCSPBadResponse
  case secOCSPBadRequest
  case secOCSPUnavailable
  case secOCSPStatusUnrecognized
  case secEndOfData
  case secIncompleteCertRevocationCheck
  case secNetworkFailure
  case secOCSPNotTrustedToAnchor
  case secRecordModified
  case secOCSPSignatureError
  case secOCSPNoSigner
  case secOCSPResponderMalformedReq
  case secOCSPResponderInternalError
  case secOCSPResponderTryLater
  case secOCSPResponderSignatureRequired
  case secOCSPResponderUnauthorized
  case secOCSPResponseNonceMismatch
  case secCodeSigningBadCertChainLength
  case secCodeSigningNoBasicConstraints
  case secCodeSigningBadPathLengthConstraint
  case secCodeSigningNoExtendedKeyUsage
  case secCodeSigningDevelopment
  case secResourceSignBadCertChainLength
  case secResourceSignBadExtKeyUsage
  case secTrustSettingDeny
  case secInvalidSubjectName
  case secUnknownQualifiedCertStatement
  case secMobileMeRequestQueued
  case secMobileMeRequestRedirected
  case secMobileMeServerError
  case secMobileMeServerNotAvailable
  case secMobileMeServerAlreadyExists
  case secMobileMeServerServiceErr
  case secMobileMeRequestAlreadyPending
  case secMobileMeNoRequestPending
  case secMobileMeCSRVerifyFailure
  case secMobileMeFailedConsistencyCheck
  case secNotInitialized
  case secInvalidHandleUsage
  case secPVCReferentNotFound
  case secFunctionIntegrityFail
  case secInternalError
  case secMemoryError
  case secInvalidData
  case secMDSError
  case secInvalidPointer
  case secSelfCheckFailed
  case secFunctionFailed
  case secModuleManifestVerifyFailed
  case secInvalidGUID
  case secInvalidHandle
  case secInvalidDBList
  case secInvalidPassthroughID
  case secInvalidNetworkAddress
  case secCRLAlreadySigned
  case secInvalidNumberOfFields
  case secVerificationFailure
  case secUnknownTag
  case secInvalidSignature
  case secInvalidName
  case secInvalidCertificateRef
  case secInvalidCertificateGroup
  case secTagNotFound
  case secInvalidQuery
  case secInvalidValue
  case secCallbackFailed
  case secACLDeleteFailed
  case secACLReplaceFailed
  case secACLAddFailed
  case secACLChangeFailed
  case secInvalidAccessCredentials
  case secInvalidRecord
  case secInvalidACL
  case secInvalidSampleValue
  case secIncompatibleVersion
  case secPrivilegeNotGranted
  case secInvalidScope
  case secPVCAlreadyConfigured
  case secInvalidPVC
  case secEMMLoadFailed
  case secEMMUnloadFailed
  case secAddinLoadFailed
  case secInvalidKeyRef
  case secInvalidKeyHierarchy
  case secAddinUnloadFailed
  case secLibraryReferenceNotFound
  case secInvalidAddinFunctionTable
  case secInvalidServiceMask
  case secModuleNotLoaded
  case secInvalidSubServiceID
  case secAttributeNotInContext
  case secModuleManagerInitializeFailed
  case secModuleManagerNotFound
  case secEventNotificationCallbackNotFound
  case secInputLengthError
  case secOutputLengthError
  case secPrivilegeNotSupported
  case secDeviceError
  case secAttachHandleBusy
  case secNotLoggedIn
  case secAlgorithmMismatch
  case secKeyUsageIncorrect
  case secKeyBlobTypeIncorrect
  case secKeyHeaderInconsistent
  case secUnsupportedKeyFormat
  case secUnsupportedKeySize
  case secInvalidKeyUsageMask
  case secUnsupportedKeyUsageMask
  case secInvalidKeyAttributeMask
  case secUnsupportedKeyAttributeMask
  case secInvalidKeyLabel
  case secUnsupportedKeyLabel
  case secInvalidKeyFormat
  case secUnsupportedVectorOfBuffers
  case secInvalidInputVector
  case secInvalidOutputVector
  case secInvalidContext
  case secInvalidAlgorithm
  case secInvalidAttributeKey
  case secMissingAttributeKey
  case secInvalidAttributeInitVector
  case secMissingAttributeInitVector
  case secInvalidAttributeSalt
  case secMissingAttributeSalt
  case secInvalidAttributePadding
  case secMissingAttributePadding
  case secInvalidAttributeRandom
  case secMissingAttributeRandom
  case secInvalidAttributeSeed
  case secMissingAttributeSeed
  case secInvalidAttributePassphrase
  case secMissingAttributePassphrase
  case secInvalidAttributeKeyLength
  case secMissingAttributeKeyLength
  case secInvalidAttributeBlockSize
  case secMissingAttributeBlockSize
  case secInvalidAttributeOutputSize
  case secMissingAttributeOutputSize
  case secInvalidAttributeRounds
  case secMissingAttributeRounds
  case secInvalidAlgorithmParms
  case secMissingAlgorithmParms
  case secInvalidAttributeLabel
  case secMissingAttributeLabel
  case secInvalidAttributeKeyType
  case secMissingAttributeKeyType
  case secInvalidAttributeMode
  case secMissingAttributeMode
  case secInvalidAttributeEffectiveBits
  case secMissingAttributeEffectiveBits
  case secInvalidAttributeStartDate
  case secMissingAttributeStartDate
  case secInvalidAttributeEndDate
  case secMissingAttributeEndDate
  case secInvalidAttributeVersion
  case secMissingAttributeVersion
  case secInvalidAttributePrime
  case secMissingAttributePrime
  case secInvalidAttributeBase
  case secMissingAttributeBase
  case secInvalidAttributeSubprime
  case secMissingAttributeSubprime
  case secInvalidAttributeIterationCount
  case secMissingAttributeIterationCount
  case secInvalidAttributeDLDBHandle
  case secMissingAttributeDLDBHandle
  case secInvalidAttributeAccessCredentials
  case secMissingAttributeAccessCredentials
  case secInvalidAttributePublicKeyFormat
  case secMissingAttributePublicKeyFormat
  case secInvalidAttributePrivateKeyFormat
  case secMissingAttributePrivateKeyFormat
  case secInvalidAttributeSymmetricKeyFormat
  case secMissingAttributeSymmetricKeyFormat
  case secInvalidAttributeWrappedKeyFormat
  case secMissingAttributeWrappedKeyFormat
  case secStagedOperationInProgress
  case secStagedOperationNotStarted
  case secVerifyFailed
  case secQuerySizeUnknown
  case secBlockSizeMismatch
  case secPublicKeyInconsistent
  case secDeviceVerifyFailed
  case secInvalidLoginName
  case secAlreadyLoggedIn
  case secInvalidDigestAlgorithm
  case secInvalidCRLGroup
  case secCertificateCannotOperate
  case secCertificateExpired
  case secCertificateNotValidYet
  case secCertificateRevoked
  case secCertificateSuspended
  case secInsufficientCredentials
  case secInvalidAction
  case secInvalidAuthority
  case secVerifyActionFailed
  case secInvalidCertAuthority
  case secInvalidCRLAuthority
  case secInvaldCRLAuthority
  case secInvalidCRLEncoding
  case secInvalidCRLType
  case secInvalidCRL
  case secInvalidFormType
  case secInvalidID
  case secInvalidIdentifier
  case secInvalidIndex
  case secInvalidPolicyIdentifiers
  case secInvalidTimeString
  case secInvalidReason
  case secInvalidRequestInputs
  case secInvalidResponseVector
  case secInvalidStopOnPolicy
  case secInvalidTuple
  case secMultipleValuesUnsupported
  case secNotTrusted
  case secNoDefaultAuthority
  case secRejectedForm
  case secRequestLost
  case secRequestRejected
  case secUnsupportedAddressType
  case secUnsupportedService
  case secInvalidTupleGroup
  case secInvalidBaseACLs
  case secInvalidTupleCredentials
  case secInvalidTupleCredendtials
  case secInvalidEncoding
  case secInvalidValidityPeriod
  case secInvalidRequestor
  case secRequestDescriptor
  case secInvalidBundleInfo
  case secInvalidCRLIndex
  case secNoFieldValues
  case secUnsupportedFieldFormat
  case secUnsupportedIndexInfo
  case secUnsupportedLocality
  case secUnsupportedNumAttributes
  case secUnsupportedNumIndexes
  case secUnsupportedNumRecordTypes
  case secFieldSpecifiedMultiple
  case secIncompatibleFieldFormat
  case secInvalidParsingModule
  case secDatabaseLocked
  case secDatastoreIsOpen
  case secMissingValue
  case secUnsupportedQueryLimits
  case secUnsupportedNumSelectionPreds
  case secUnsupportedOperator
  case secInvalidDBLocation
  case secInvalidAccessRequest
  case secInvalidIndexInfo
  case secInvalidNewOwner
  case secInvalidModifyMode
  case secMissingRequiredExtension
  case secExtendedKeyUsageNotCritical
  case secTimestampMissing
  case secTimestampInvalid
  case secTimestampNotTrusted
  case secTimestampServiceNotAvailable
  case secTimestampBadAlg
  case secTimestampBadRequest
  case secTimestampBadDataFormat
  case secTimestampTimeNotAvailable
  case secTimestampUnacceptedPolicy
  case secTimestampUnacceptedExtension
  case secTimestampAddInfoNotAvailable
  case secTimestampSystemFailure
  case secSigningTimeMissing
  case secTimestampRejection
  case secTimestampWaiting
  case secTimestampRevocationWarning
  case secTimestampRevocationNotification
  case secCertificatePolicyNotAllowed
  case secCertificateNameNotAllowed
  case secCertificateValidityPeriodTooLong
  case secCertificateIsCA
  case secCertificateDuplicateExtension
  case sslProtocol
  case sslNegotiation
  case sslFatalAlert
  case sslWouldBlock
  case sslSessionNotFound
  case sslClosedGraceful
  case sslClosedAbort
  case sslXCertChainInvalid
  case sslBadCert
  case sslCrypto
  case sslInternal
  case sslModuleAttach
  case sslUnknownRootCert
  case sslNoRootCert
  case sslCertExpired
  case sslCertNotYetValid
  case sslClosedNoNotify
  case sslBufferOverflow
  case sslBadCipherSuite
  case sslPeerUnexpectedMsg
  case sslPeerBadRecordMac
  case sslPeerDecryptionFail
  case sslPeerRecordOverflow
  case sslPeerDecompressFail
  case sslPeerHandshakeFail
  case sslPeerBadCert
  case sslPeerUnsupportedCert
  case sslPeerCertRevoked
  case sslPeerCertExpired
  case sslPeerCertUnknown
  case sslIllegalParam
  case sslPeerUnknownCA
  case sslPeerAccessDenied
  case sslPeerDecodeError
  case sslPeerDecryptError
  case sslPeerExportRestriction
  case sslPeerProtocolVersion
  case sslPeerInsufficientSecurity
  case sslPeerInternalError
  case sslPeerUserCancelled
  case sslPeerNoRenegotiation
  case sslPeerAuthCompleted
  case sslClientCertRequested
  case sslHostNameMismatch
  case sslConnectionRefused
  case sslDecryptionFail
  case sslBadRecordMac
  case sslRecordOverflow
  case sslBadConfiguration
  case sslUnexpectedRecord
  case sslWeakPeerEphemeralDHKey
  case sslClientHelloReceived
  case sslTransportReset
  case sslNetworkTimeout
  case sslConfigurationFailed
  case sslUnsupportedExtension
  case sslUnexpectedMessage
  case sslDecompressFail
  case sslHandshakeFail
  case sslDecodeError
  case sslInappropriateFallback
  case sslMissingExtension
  case sslBadCertificateStatusResponse
  case sslCertificateRequired
  case sslUnknownPSKIdentity
  case sslUnrecognizedName
  case sslATSViolation
  case sslATSMinimumVersionViolation
  case sslATSCiphersuiteViolation
  case sslATSMinimumKeySizeViolation
  case sslATSLeafCertificateHashAlgorithmViolation
  case sslATSCertificateHashAlgorithmViolation
  case sslATSCertificateTrustViolation
  case sslEarlyDataRejected

  var errorDescription: String? {
    switch self {
    case .secSuccess:
      return "sec success"
    case .secUnimplemented:
      return "sec unimplemented"
    case .secDiskFull:
      return "sec disk full"
    case .secIO:
      return "sec io"
    case .secOpWr:
      return "sec op wr"
    case .secParam:
      return "sec param"
    case .secWrPerm:
      return "sec wr perm"
    case .secAllocate:
      return "sec allocate"
    case .secUserCanceled:
      return "sec user canceled"
    case .secBadReq:
      return "sec bad req"
    case .secInternalComponent:
      return "sec internal component"
    case .secCoreFoundationUnknown:
      return "sec core foundation unknown"
    case .secMissingEntitlement:
      return "sec missing entitlement"
    case .secRestrictedAPI:
      return "sec restricted api"
    case .secNotAvailable:
      return "sec not available"
    case .secReadOnly:
      return "sec read only"
    case .secAuthFailed:
      return "sec auth failed"
    case .secNoSuchKeychain:
      return "sec no such keychain"
    case .secInvalidKeychain:
      return "sec invalid keychain"
    case .secDuplicateKeychain:
      return "sec duplicate keychain"
    case .secDuplicateCallback:
      return "sec duplicate callback"
    case .secInvalidCallback:
      return "sec invalid callback"
    case .secDuplicateItem:
      return "sec duplicate item"
    case .secItemNotFound:
      return "sec item not found"
    case .secBufferTooSmall:
      return "sec buffer too small"
    case .secDataTooLarge:
      return "sec data too large"
    case .secNoSuchAttr:
      return "sec no such attr"
    case .secInvalidItemRef:
      return "sec invalid item ref"
    case .secInvalidSearchRef:
      return "sec invalid search ref"
    case .secNoSuchClass:
      return "sec no such class"
    case .secNoDefaultKeychain:
      return "sec no default keychain"
    case .secInteractionNotAllowed:
      return "sec interaction not allowed"
    case .secReadOnlyAttr:
      return "sec read only attr"
    case .secWrongSecVersion:
      return "sec wrong sec version"
    case .secKeySizeNotAllowed:
      return "sec key size not allowed"
    case .secNoStorageModule:
      return "sec no storage module"
    case .secNoCertificateModule:
      return "sec no certificate module"
    case .secNoPolicyModule:
      return "sec no policy module"
    case .secInteractionRequired:
      return "sec interaction required"
    case .secDataNotAvailable:
      return "sec data not available"
    case .secDataNotModifiable:
      return "sec data not modifiable"
    case .secCreateChainFailed:
      return "sec create chain failed"
    case .secInvalidPrefsDomain:
      return "sec invalid prefs domain"
    case .secInDarkWake:
      return "sec in dark wake"
    case .secACLNotSimple:
      return "sec acl not simple"
    case .secPolicyNotFound:
      return "sec policy not found"
    case .secInvalidTrustSetting:
      return "sec invalid trust setting"
    case .secNoAccessForItem:
      return "sec no access for item"
    case .secInvalidOwnerEdit:
      return "sec invalid owner edit"
    case .secTrustNotAvailable:
      return "sec trust not available"
    case .secUnsupportedFormat:
      return "sec unsupported format"
    case .secUnknownFormat:
      return "sec unknown format"
    case .secKeyIsSensitive:
      return "sec key is sensitive"
    case .secMultiplePrivKeys:
      return "sec multiple priv keys"
    case .secPassphraseRequired:
      return "sec passphrase required"
    case .secInvalidPasswordRef:
      return "sec invalid password ref"
    case .secInvalidTrustSettings:
      return "sec invalid trust settings"
    case .secNoTrustSettings:
      return "sec no trust settings"
    case .secPkcs12VerifyFailure:
      return "sec pkcs 12 verify failure"
    case .secNotSigner:
      return "sec not signer"
    case .secDecode:
      return "sec decode"
    case .secServiceNotAvailable:
      return "sec service not available"
    case .secInsufficientClientID:
      return "sec insufficient client id"
    case .secDeviceReset:
      return "sec device reset"
    case .secDeviceFailed:
      return "sec device failed"
    case .secAppleAddAppACLSubject:
      return "sec apple add app acl subject"
    case .secApplePublicKeyIncomplete:
      return "sec apple public key incomplete"
    case .secAppleSignatureMismatch:
      return "sec apple signature mismatch"
    case .secAppleInvalidKeyStartDate:
      return "sec apple invalid key start date"
    case .secAppleInvalidKeyEndDate:
      return "sec apple invalid key end date"
    case .secConversionError:
      return "sec conversion error"
    case .secAppleSSLv2Rollback:
      return "sec apple ss lv 2 rollback"
    case .secQuotaExceeded:
      return "sec quota exceeded"
    case .secFileTooBig:
      return "sec file too big"
    case .secInvalidDatabaseBlob:
      return "sec invalid database blob"
    case .secInvalidKeyBlob:
      return "sec invalid key blob"
    case .secIncompatibleDatabaseBlob:
      return "sec incompatible database blob"
    case .secIncompatibleKeyBlob:
      return "sec incompatible key blob"
    case .secHostNameMismatch:
      return "sec host name mismatch"
    case .secUnknownCriticalExtensionFlag:
      return "sec unknown critical extension flag"
    case .secNoBasicConstraints:
      return "sec no basic constraints"
    case .secNoBasicConstraintsCA:
      return "sec no basic constraints ca"
    case .secInvalidAuthorityKeyID:
      return "sec invalid authority key id"
    case .secInvalidSubjectKeyID:
      return "sec invalid subject key id"
    case .secInvalidKeyUsageForPolicy:
      return "sec invalid key usage for policy"
    case .secInvalidExtendedKeyUsage:
      return "sec invalid extended key usage"
    case .secInvalidIDLinkage:
      return "sec invalid id linkage"
    case .secPathLengthConstraintExceeded:
      return "sec path length constraint exceeded"
    case .secInvalidRoot:
      return "sec invalid root"
    case .secCRLExpired:
      return "sec crl expired"
    case .secCRLNotValidYet:
      return "sec crl not valid yet"
    case .secCRLNotFound:
      return "sec crl not found"
    case .secCRLServerDown:
      return "sec crl server down"
    case .secCRLBadURI:
      return "sec crl bad uri"
    case .secUnknownCertExtension:
      return "sec unknown cert extension"
    case .secUnknownCRLExtension:
      return "sec unknown crl extension"
    case .secCRLNotTrusted:
      return "sec crl not trusted"
    case .secCRLPolicyFailed:
      return "sec crl policy failed"
    case .secIDPFailure:
      return "sec idp failure"
    case .secSMIMEEmailAddressesNotFound:
      return "sec smime email addresses not found"
    case .secSMIMEBadExtendedKeyUsage:
      return "sec smime bad extended key usage"
    case .secSMIMEBadKeyUsage:
      return "sec smime bad key usage"
    case .secSMIMEKeyUsageNotCritical:
      return "sec smime key usage not critical"
    case .secSMIMENoEmailAddress:
      return "sec smime no email address"
    case .secSMIMESubjAltNameNotCritical:
      return "sec smime subj alt name not critical"
    case .secSSLBadExtendedKeyUsage:
      return "sec ssl bad extended key usage"
    case .secOCSPBadResponse:
      return "sec ocsp bad response"
    case .secOCSPBadRequest:
      return "sec ocsp bad request"
    case .secOCSPUnavailable:
      return "sec ocsp unavailable"
    case .secOCSPStatusUnrecognized:
      return "sec ocsp status unrecognized"
    case .secEndOfData:
      return "sec end of data"
    case .secIncompleteCertRevocationCheck:
      return "sec incomplete cert revocation check"
    case .secNetworkFailure:
      return "sec network failure"
    case .secOCSPNotTrustedToAnchor:
      return "sec ocsp not trusted to anchor"
    case .secRecordModified:
      return "sec record modified"
    case .secOCSPSignatureError:
      return "sec ocsp signature error"
    case .secOCSPNoSigner:
      return "sec ocsp no signer"
    case .secOCSPResponderMalformedReq:
      return "sec ocsp responder malformed req"
    case .secOCSPResponderInternalError:
      return "sec ocsp responder internal error"
    case .secOCSPResponderTryLater:
      return "sec ocsp responder try later"
    case .secOCSPResponderSignatureRequired:
      return "sec ocsp responder signature required"
    case .secOCSPResponderUnauthorized:
      return "sec ocsp responder unauthorized"
    case .secOCSPResponseNonceMismatch:
      return "sec ocsp response nonce mismatch"
    case .secCodeSigningBadCertChainLength:
      return "sec code signing bad cert chain length"
    case .secCodeSigningNoBasicConstraints:
      return "sec code signing no basic constraints"
    case .secCodeSigningBadPathLengthConstraint:
      return "sec code signing bad path length constraint"
    case .secCodeSigningNoExtendedKeyUsage:
      return "sec code signing no extended key usage"
    case .secCodeSigningDevelopment:
      return "sec code signing development"
    case .secResourceSignBadCertChainLength:
      return "sec resource sign bad cert chain length"
    case .secResourceSignBadExtKeyUsage:
      return "sec resource sign bad ext key usage"
    case .secTrustSettingDeny:
      return "sec trust setting deny"
    case .secInvalidSubjectName:
      return "sec invalid subject name"
    case .secUnknownQualifiedCertStatement:
      return "sec unknown qualified cert statement"
    case .secMobileMeRequestQueued:
      return "sec mobile me request queued"
    case .secMobileMeRequestRedirected:
      return "sec mobile me request redirected"
    case .secMobileMeServerError:
      return "sec mobile me server error"
    case .secMobileMeServerNotAvailable:
      return "sec mobile me server not available"
    case .secMobileMeServerAlreadyExists:
      return "sec mobile me server already exists"
    case .secMobileMeServerServiceErr:
      return "sec mobile me server service err"
    case .secMobileMeRequestAlreadyPending:
      return "sec mobile me request already pending"
    case .secMobileMeNoRequestPending:
      return "sec mobile me no request pending"
    case .secMobileMeCSRVerifyFailure:
      return "sec mobile me csr verify failure"
    case .secMobileMeFailedConsistencyCheck:
      return "sec mobile me failed consistency check"
    case .secNotInitialized:
      return "sec not initialized"
    case .secInvalidHandleUsage:
      return "sec invalid handle usage"
    case .secPVCReferentNotFound:
      return "sec pvc referent not found"
    case .secFunctionIntegrityFail:
      return "sec function integrity fail"
    case .secInternalError:
      return "sec internal error"
    case .secMemoryError:
      return "sec memory error"
    case .secInvalidData:
      return "sec invalid data"
    case .secMDSError:
      return "sec mds error"
    case .secInvalidPointer:
      return "sec invalid pointer"
    case .secSelfCheckFailed:
      return "sec self check failed"
    case .secFunctionFailed:
      return "sec function failed"
    case .secModuleManifestVerifyFailed:
      return "sec module manifest verify failed"
    case .secInvalidGUID:
      return "sec invalid guid"
    case .secInvalidHandle:
      return "sec invalid handle"
    case .secInvalidDBList:
      return "sec invalid db list"
    case .secInvalidPassthroughID:
      return "sec invalid passthrough id"
    case .secInvalidNetworkAddress:
      return "sec invalid network address"
    case .secCRLAlreadySigned:
      return "sec crl already signed"
    case .secInvalidNumberOfFields:
      return "sec invalid number of fields"
    case .secVerificationFailure:
      return "sec verification failure"
    case .secUnknownTag:
      return "sec unknown tag"
    case .secInvalidSignature:
      return "sec invalid signature"
    case .secInvalidName:
      return "sec invalid name"
    case .secInvalidCertificateRef:
      return "sec invalid certificate ref"
    case .secInvalidCertificateGroup:
      return "sec invalid certificate group"
    case .secTagNotFound:
      return "sec tag not found"
    case .secInvalidQuery:
      return "sec invalid query"
    case .secInvalidValue:
      return "sec invalid value"
    case .secCallbackFailed:
      return "sec callback failed"
    case .secACLDeleteFailed:
      return "sec acl delete failed"
    case .secACLReplaceFailed:
      return "sec acl replace failed"
    case .secACLAddFailed:
      return "sec acl add failed"
    case .secACLChangeFailed:
      return "sec acl change failed"
    case .secInvalidAccessCredentials:
      return "sec invalid access credentials"
    case .secInvalidRecord:
      return "sec invalid record"
    case .secInvalidACL:
      return "sec invalid acl"
    case .secInvalidSampleValue:
      return "sec invalid sample value"
    case .secIncompatibleVersion:
      return "sec incompatible version"
    case .secPrivilegeNotGranted:
      return "sec privilege not granted"
    case .secInvalidScope:
      return "sec invalid scope"
    case .secPVCAlreadyConfigured:
      return "sec pvc already configured"
    case .secInvalidPVC:
      return "sec invalid pvc"
    case .secEMMLoadFailed:
      return "sec emm load failed"
    case .secEMMUnloadFailed:
      return "sec emm unload failed"
    case .secAddinLoadFailed:
      return "sec addin load failed"
    case .secInvalidKeyRef:
      return "sec invalid key ref"
    case .secInvalidKeyHierarchy:
      return "sec invalid key hierarchy"
    case .secAddinUnloadFailed:
      return "sec addin unload failed"
    case .secLibraryReferenceNotFound:
      return "sec library reference not found"
    case .secInvalidAddinFunctionTable:
      return "sec invalid addin function table"
    case .secInvalidServiceMask:
      return "sec invalid service mask"
    case .secModuleNotLoaded:
      return "sec module not loaded"
    case .secInvalidSubServiceID:
      return "sec invalid sub service id"
    case .secAttributeNotInContext:
      return "sec attribute not in context"
    case .secModuleManagerInitializeFailed:
      return "sec module manager initialize failed"
    case .secModuleManagerNotFound:
      return "sec module manager not found"
    case .secEventNotificationCallbackNotFound:
      return "sec event notification callback not found"
    case .secInputLengthError:
      return "sec input length error"
    case .secOutputLengthError:
      return "sec output length error"
    case .secPrivilegeNotSupported:
      return "sec privilege not supported"
    case .secDeviceError:
      return "sec device error"
    case .secAttachHandleBusy:
      return "sec attach handle busy"
    case .secNotLoggedIn:
      return "sec not logged in"
    case .secAlgorithmMismatch:
      return "sec algorithm mismatch"
    case .secKeyUsageIncorrect:
      return "sec key usage incorrect"
    case .secKeyBlobTypeIncorrect:
      return "sec key blob type incorrect"
    case .secKeyHeaderInconsistent:
      return "sec key header inconsistent"
    case .secUnsupportedKeyFormat:
      return "sec unsupported key format"
    case .secUnsupportedKeySize:
      return "sec unsupported key size"
    case .secInvalidKeyUsageMask:
      return "sec invalid key usage mask"
    case .secUnsupportedKeyUsageMask:
      return "sec unsupported key usage mask"
    case .secInvalidKeyAttributeMask:
      return "sec invalid key attribute mask"
    case .secUnsupportedKeyAttributeMask:
      return "sec unsupported key attribute mask"
    case .secInvalidKeyLabel:
      return "sec invalid key label"
    case .secUnsupportedKeyLabel:
      return "sec unsupported key label"
    case .secInvalidKeyFormat:
      return "sec invalid key format"
    case .secUnsupportedVectorOfBuffers:
      return "sec unsupported vector of buffers"
    case .secInvalidInputVector:
      return "sec invalid input vector"
    case .secInvalidOutputVector:
      return "sec invalid output vector"
    case .secInvalidContext:
      return "sec invalid context"
    case .secInvalidAlgorithm:
      return "sec invalid algorithm"
    case .secInvalidAttributeKey:
      return "sec invalid attribute key"
    case .secMissingAttributeKey:
      return "sec missing attribute key"
    case .secInvalidAttributeInitVector:
      return "sec invalid attribute init vector"
    case .secMissingAttributeInitVector:
      return "sec missing attribute init vector"
    case .secInvalidAttributeSalt:
      return "sec invalid attribute salt"
    case .secMissingAttributeSalt:
      return "sec missing attribute salt"
    case .secInvalidAttributePadding:
      return "sec invalid attribute padding"
    case .secMissingAttributePadding:
      return "sec missing attribute padding"
    case .secInvalidAttributeRandom:
      return "sec invalid attribute random"
    case .secMissingAttributeRandom:
      return "sec missing attribute random"
    case .secInvalidAttributeSeed:
      return "sec invalid attribute seed"
    case .secMissingAttributeSeed:
      return "sec missing attribute seed"
    case .secInvalidAttributePassphrase:
      return "sec invalid attribute passphrase"
    case .secMissingAttributePassphrase:
      return "sec missing attribute passphrase"
    case .secInvalidAttributeKeyLength:
      return "sec invalid attribute key length"
    case .secMissingAttributeKeyLength:
      return "sec missing attribute key length"
    case .secInvalidAttributeBlockSize:
      return "sec invalid attribute block size"
    case .secMissingAttributeBlockSize:
      return "sec missing attribute block size"
    case .secInvalidAttributeOutputSize:
      return "sec invalid attribute output size"
    case .secMissingAttributeOutputSize:
      return "sec missing attribute output size"
    case .secInvalidAttributeRounds:
      return "sec invalid attribute rounds"
    case .secMissingAttributeRounds:
      return "sec missing attribute rounds"
    case .secInvalidAlgorithmParms:
      return "sec invalid algorithm parms"
    case .secMissingAlgorithmParms:
      return "sec missing algorithm parms"
    case .secInvalidAttributeLabel:
      return "sec invalid attribute label"
    case .secMissingAttributeLabel:
      return "sec missing attribute label"
    case .secInvalidAttributeKeyType:
      return "sec invalid attribute key type"
    case .secMissingAttributeKeyType:
      return "sec missing attribute key type"
    case .secInvalidAttributeMode:
      return "sec invalid attribute mode"
    case .secMissingAttributeMode:
      return "sec missing attribute mode"
    case .secInvalidAttributeEffectiveBits:
      return "sec invalid attribute effective bits"
    case .secMissingAttributeEffectiveBits:
      return "sec missing attribute effective bits"
    case .secInvalidAttributeStartDate:
      return "sec invalid attribute start date"
    case .secMissingAttributeStartDate:
      return "sec missing attribute start date"
    case .secInvalidAttributeEndDate:
      return "sec invalid attribute end date"
    case .secMissingAttributeEndDate:
      return "sec missing attribute end date"
    case .secInvalidAttributeVersion:
      return "sec invalid attribute version"
    case .secMissingAttributeVersion:
      return "sec missing attribute version"
    case .secInvalidAttributePrime:
      return "sec invalid attribute prime"
    case .secMissingAttributePrime:
      return "sec missing attribute prime"
    case .secInvalidAttributeBase:
      return "sec invalid attribute base"
    case .secMissingAttributeBase:
      return "sec missing attribute base"
    case .secInvalidAttributeSubprime:
      return "sec invalid attribute subprime"
    case .secMissingAttributeSubprime:
      return "sec missing attribute subprime"
    case .secInvalidAttributeIterationCount:
      return "sec invalid attribute iteration count"
    case .secMissingAttributeIterationCount:
      return "sec missing attribute iteration count"
    case .secInvalidAttributeDLDBHandle:
      return "sec invalid attribute dldb handle"
    case .secMissingAttributeDLDBHandle:
      return "sec missing attribute dldb handle"
    case .secInvalidAttributeAccessCredentials:
      return "sec invalid attribute access credentials"
    case .secMissingAttributeAccessCredentials:
      return "sec missing attribute access credentials"
    case .secInvalidAttributePublicKeyFormat:
      return "sec invalid attribute public key format"
    case .secMissingAttributePublicKeyFormat:
      return "sec missing attribute public key format"
    case .secInvalidAttributePrivateKeyFormat:
      return "sec invalid attribute private key format"
    case .secMissingAttributePrivateKeyFormat:
      return "sec missing attribute private key format"
    case .secInvalidAttributeSymmetricKeyFormat:
      return "sec invalid attribute symmetric key format"
    case .secMissingAttributeSymmetricKeyFormat:
      return "sec missing attribute symmetric key format"
    case .secInvalidAttributeWrappedKeyFormat:
      return "sec invalid attribute wrapped key format"
    case .secMissingAttributeWrappedKeyFormat:
      return "sec missing attribute wrapped key format"
    case .secStagedOperationInProgress:
      return "sec staged operation in progress"
    case .secStagedOperationNotStarted:
      return "sec staged operation not started"
    case .secVerifyFailed:
      return "sec verify failed"
    case .secQuerySizeUnknown:
      return "sec query size unknown"
    case .secBlockSizeMismatch:
      return "sec block size mismatch"
    case .secPublicKeyInconsistent:
      return "sec public key inconsistent"
    case .secDeviceVerifyFailed:
      return "sec device verify failed"
    case .secInvalidLoginName:
      return "sec invalid login name"
    case .secAlreadyLoggedIn:
      return "sec already logged in"
    case .secInvalidDigestAlgorithm:
      return "sec invalid digest algorithm"
    case .secInvalidCRLGroup:
      return "sec invalid crl group"
    case .secCertificateCannotOperate:
      return "sec certificate cannot operate"
    case .secCertificateExpired:
      return "sec certificate expired"
    case .secCertificateNotValidYet:
      return "sec certificate not valid yet"
    case .secCertificateRevoked:
      return "sec certificate revoked"
    case .secCertificateSuspended:
      return "sec certificate suspended"
    case .secInsufficientCredentials:
      return "sec insufficient credentials"
    case .secInvalidAction:
      return "sec invalid action"
    case .secInvalidAuthority:
      return "sec invalid authority"
    case .secVerifyActionFailed:
      return "sec verify action failed"
    case .secInvalidCertAuthority:
      return "sec invalid cert authority"
    case .secInvalidCRLAuthority:
      return "sec invalid crl authority"
    case .secInvaldCRLAuthority:
      return "sec invald crl authority"
    case .secInvalidCRLEncoding:
      return "sec invalid crl encoding"
    case .secInvalidCRLType:
      return "sec invalid crl type"
    case .secInvalidCRL:
      return "sec invalid crl"
    case .secInvalidFormType:
      return "sec invalid form type"
    case .secInvalidID:
      return "sec invalid id"
    case .secInvalidIdentifier:
      return "sec invalid identifier"
    case .secInvalidIndex:
      return "sec invalid index"
    case .secInvalidPolicyIdentifiers:
      return "sec invalid policy identifiers"
    case .secInvalidTimeString:
      return "sec invalid time string"
    case .secInvalidReason:
      return "sec invalid reason"
    case .secInvalidRequestInputs:
      return "sec invalid request inputs"
    case .secInvalidResponseVector:
      return "sec invalid response vector"
    case .secInvalidStopOnPolicy:
      return "sec invalid stop on policy"
    case .secInvalidTuple:
      return "sec invalid tuple"
    case .secMultipleValuesUnsupported:
      return "sec multiple values unsupported"
    case .secNotTrusted:
      return "sec not trusted"
    case .secNoDefaultAuthority:
      return "sec no default authority"
    case .secRejectedForm:
      return "sec rejected form"
    case .secRequestLost:
      return "sec request lost"
    case .secRequestRejected:
      return "sec request rejected"
    case .secUnsupportedAddressType:
      return "sec unsupported address type"
    case .secUnsupportedService:
      return "sec unsupported service"
    case .secInvalidTupleGroup:
      return "sec invalid tuple group"
    case .secInvalidBaseACLs:
      return "sec invalid base ac ls"
    case .secInvalidTupleCredentials:
      return "sec invalid tuple credentials"
    case .secInvalidTupleCredendtials:
      return "sec invalid tuple credendtials"
    case .secInvalidEncoding:
      return "sec invalid encoding"
    case .secInvalidValidityPeriod:
      return "sec invalid validity period"
    case .secInvalidRequestor:
      return "sec invalid requestor"
    case .secRequestDescriptor:
      return "sec request descriptor"
    case .secInvalidBundleInfo:
      return "sec invalid bundle info"
    case .secInvalidCRLIndex:
      return "sec invalid crl index"
    case .secNoFieldValues:
      return "sec no field values"
    case .secUnsupportedFieldFormat:
      return "sec unsupported field format"
    case .secUnsupportedIndexInfo:
      return "sec unsupported index info"
    case .secUnsupportedLocality:
      return "sec unsupported locality"
    case .secUnsupportedNumAttributes:
      return "sec unsupported num attributes"
    case .secUnsupportedNumIndexes:
      return "sec unsupported num indexes"
    case .secUnsupportedNumRecordTypes:
      return "sec unsupported num record types"
    case .secFieldSpecifiedMultiple:
      return "sec field specified multiple"
    case .secIncompatibleFieldFormat:
      return "sec incompatible field format"
    case .secInvalidParsingModule:
      return "sec invalid parsing module"
    case .secDatabaseLocked:
      return "sec database locked"
    case .secDatastoreIsOpen:
      return "sec datastore is open"
    case .secMissingValue:
      return "sec missing value"
    case .secUnsupportedQueryLimits:
      return "sec unsupported query limits"
    case .secUnsupportedNumSelectionPreds:
      return "sec unsupported num selection preds"
    case .secUnsupportedOperator:
      return "sec unsupported operator"
    case .secInvalidDBLocation:
      return "sec invalid db location"
    case .secInvalidAccessRequest:
      return "sec invalid access request"
    case .secInvalidIndexInfo:
      return "sec invalid index info"
    case .secInvalidNewOwner:
      return "sec invalid new owner"
    case .secInvalidModifyMode:
      return "sec invalid modify mode"
    case .secMissingRequiredExtension:
      return "sec missing required extension"
    case .secExtendedKeyUsageNotCritical:
      return "sec extended key usage not critical"
    case .secTimestampMissing:
      return "sec timestamp missing"
    case .secTimestampInvalid:
      return "sec timestamp invalid"
    case .secTimestampNotTrusted:
      return "sec timestamp not trusted"
    case .secTimestampServiceNotAvailable:
      return "sec timestamp service not available"
    case .secTimestampBadAlg:
      return "sec timestamp bad alg"
    case .secTimestampBadRequest:
      return "sec timestamp bad request"
    case .secTimestampBadDataFormat:
      return "sec timestamp bad data format"
    case .secTimestampTimeNotAvailable:
      return "sec timestamp time not available"
    case .secTimestampUnacceptedPolicy:
      return "sec timestamp unaccepted policy"
    case .secTimestampUnacceptedExtension:
      return "sec timestamp unaccepted extension"
    case .secTimestampAddInfoNotAvailable:
      return "sec timestamp add info not available"
    case .secTimestampSystemFailure:
      return "sec timestamp system failure"
    case .secSigningTimeMissing:
      return "sec signing time missing"
    case .secTimestampRejection:
      return "sec timestamp rejection"
    case .secTimestampWaiting:
      return "sec timestamp waiting"
    case .secTimestampRevocationWarning:
      return "sec timestamp revocation warning"
    case .secTimestampRevocationNotification:
      return "sec timestamp revocation notification"
    case .secCertificatePolicyNotAllowed:
      return "sec certificate policy not allowed"
    case .secCertificateNameNotAllowed:
      return "sec certificate name not allowed"
    case .secCertificateValidityPeriodTooLong:
      return "sec certificate validity period too long"
    case .secCertificateIsCA:
      return "sec certificate is ca"
    case .secCertificateDuplicateExtension:
      return "sec certificate duplicate extension"
    case .sslProtocol:
      return "ssl protocol"
    case .sslNegotiation:
      return "ssl negotiation"
    case .sslFatalAlert:
      return "ssl fatal alert"
    case .sslWouldBlock:
      return "ssl would block"
    case .sslSessionNotFound:
      return "ssl session not found"
    case .sslClosedGraceful:
      return "ssl closed graceful"
    case .sslClosedAbort:
      return "ssl closed abort"
    case .sslXCertChainInvalid:
      return "sslx cert chain invalid"
    case .sslBadCert:
      return "ssl bad cert"
    case .sslCrypto:
      return "ssl crypto"
    case .sslInternal:
      return "ssl internal"
    case .sslModuleAttach:
      return "ssl module attach"
    case .sslUnknownRootCert:
      return "ssl unknown root cert"
    case .sslNoRootCert:
      return "ssl no root cert"
    case .sslCertExpired:
      return "ssl cert expired"
    case .sslCertNotYetValid:
      return "ssl cert not yet valid"
    case .sslClosedNoNotify:
      return "ssl closed no notify"
    case .sslBufferOverflow:
      return "ssl buffer overflow"
    case .sslBadCipherSuite:
      return "ssl bad cipher suite"
    case .sslPeerUnexpectedMsg:
      return "ssl peer unexpected msg"
    case .sslPeerBadRecordMac:
      return "ssl peer bad record mac"
    case .sslPeerDecryptionFail:
      return "ssl peer decryption fail"
    case .sslPeerRecordOverflow:
      return "ssl peer record overflow"
    case .sslPeerDecompressFail:
      return "ssl peer decompress fail"
    case .sslPeerHandshakeFail:
      return "ssl peer handshake fail"
    case .sslPeerBadCert:
      return "ssl peer bad cert"
    case .sslPeerUnsupportedCert:
      return "ssl peer unsupported cert"
    case .sslPeerCertRevoked:
      return "ssl peer cert revoked"
    case .sslPeerCertExpired:
      return "ssl peer cert expired"
    case .sslPeerCertUnknown:
      return "ssl peer cert unknown"
    case .sslIllegalParam:
      return "ssl illegal param"
    case .sslPeerUnknownCA:
      return "ssl peer unknown ca"
    case .sslPeerAccessDenied:
      return "ssl peer access denied"
    case .sslPeerDecodeError:
      return "ssl peer decode error"
    case .sslPeerDecryptError:
      return "ssl peer decrypt error"
    case .sslPeerExportRestriction:
      return "ssl peer export restriction"
    case .sslPeerProtocolVersion:
      return "ssl peer protocol version"
    case .sslPeerInsufficientSecurity:
      return "ssl peer insufficient security"
    case .sslPeerInternalError:
      return "ssl peer internal error"
    case .sslPeerUserCancelled:
      return "ssl peer user cancelled"
    case .sslPeerNoRenegotiation:
      return "ssl peer no renegotiation"
    case .sslPeerAuthCompleted:
      return "ssl peer auth completed"
    case .sslClientCertRequested:
      return "ssl client cert requested"
    case .sslHostNameMismatch:
      return "ssl host name mismatch"
    case .sslConnectionRefused:
      return "ssl connection refused"
    case .sslDecryptionFail:
      return "ssl decryption fail"
    case .sslBadRecordMac:
      return "ssl bad record mac"
    case .sslRecordOverflow:
      return "ssl record overflow"
    case .sslBadConfiguration:
      return "ssl bad configuration"
    case .sslUnexpectedRecord:
      return "ssl unexpected record"
    case .sslWeakPeerEphemeralDHKey:
      return "ssl weak peer ephemeral dh key"
    case .sslClientHelloReceived:
      return "ssl client hello received"
    case .sslTransportReset:
      return "ssl transport reset"
    case .sslNetworkTimeout:
      return "ssl network timeout"
    case .sslConfigurationFailed:
      return "ssl configuration failed"
    case .sslUnsupportedExtension:
      return "ssl unsupported extension"
    case .sslUnexpectedMessage:
      return "ssl unexpected message"
    case .sslDecompressFail:
      return "ssl decompress fail"
    case .sslHandshakeFail:
      return "ssl handshake fail"
    case .sslDecodeError:
      return "ssl decode error"
    case .sslInappropriateFallback:
      return "ssl inappropriate fallback"
    case .sslMissingExtension:
      return "ssl missing extension"
    case .sslBadCertificateStatusResponse:
      return "ssl bad certificate status response"
    case .sslCertificateRequired:
      return "ssl certificate required"
    case .sslUnknownPSKIdentity:
      return "ssl unknown psk identity"
    case .sslUnrecognizedName:
      return "ssl unrecognized name"
    case .sslATSViolation:
      return "sslats violation"
    case .sslATSMinimumVersionViolation:
      return "sslats minimum version violation"
    case .sslATSCiphersuiteViolation:
      return "sslats ciphersuite violation"
    case .sslATSMinimumKeySizeViolation:
      return "sslats minimum key size violation"
    case .sslATSLeafCertificateHashAlgorithmViolation:
      return "sslats leaf certificate hash algorithm violation"
    case .sslATSCertificateHashAlgorithmViolation:
      return "sslats certificate hash algorithm violation"
    case .sslATSCertificateTrustViolation:
      return "sslats certificate trust violation"
    case .sslEarlyDataRejected:
      return "ssl early data rejected"
    }
  }

  init(rawValue: OSStatus) {
    switch rawValue {
    case errSecSuccess:
      self = .secSuccess
    case errSecUnimplemented:
      self = .secUnimplemented
    case errSecDiskFull:
      self = .secDiskFull
    case errSecIO:
      self = .secIO
    case errSecOpWr:
      self = .secOpWr
    case errSecParam:
      self = .secParam
    case errSecWrPerm:
      self = .secWrPerm
    case errSecAllocate:
      self = .secAllocate
    case errSecUserCanceled:
      self = .secUserCanceled
    case errSecBadReq:
      self = .secBadReq
    case errSecInternalComponent:
      self = .secInternalComponent
    case errSecCoreFoundationUnknown:
      self = .secCoreFoundationUnknown
    case errSecMissingEntitlement:
      self = .secMissingEntitlement
    case errSecRestrictedAPI:
      self = .secRestrictedAPI
    case errSecNotAvailable:
      self = .secNotAvailable
    case errSecReadOnly:
      self = .secReadOnly
    case errSecAuthFailed:
      self = .secAuthFailed
    case errSecNoSuchKeychain:
      self = .secNoSuchKeychain
    case errSecInvalidKeychain:
      self = .secInvalidKeychain
    case errSecDuplicateKeychain:
      self = .secDuplicateKeychain
    case errSecDuplicateCallback:
      self = .secDuplicateCallback
    case errSecInvalidCallback:
      self = .secInvalidCallback
    case errSecDuplicateItem:
      self = .secDuplicateItem
    case errSecItemNotFound:
      self = .secItemNotFound
    case errSecBufferTooSmall:
      self = .secBufferTooSmall
    case errSecDataTooLarge:
      self = .secDataTooLarge
    case errSecNoSuchAttr:
      self = .secNoSuchAttr
    case errSecInvalidItemRef:
      self = .secInvalidItemRef
    case errSecInvalidSearchRef:
      self = .secInvalidSearchRef
    case errSecNoSuchClass:
      self = .secNoSuchClass
    case errSecNoDefaultKeychain:
      self = .secNoDefaultKeychain
    case errSecInteractionNotAllowed:
      self = .secInteractionNotAllowed
    case errSecReadOnlyAttr:
      self = .secReadOnlyAttr
    case errSecWrongSecVersion:
      self = .secWrongSecVersion
    case errSecKeySizeNotAllowed:
      self = .secKeySizeNotAllowed
    case errSecNoStorageModule:
      self = .secNoStorageModule
    case errSecNoCertificateModule:
      self = .secNoCertificateModule
    case errSecNoPolicyModule:
      self = .secNoPolicyModule
    case errSecInteractionRequired:
      self = .secInteractionRequired
    case errSecDataNotAvailable:
      self = .secDataNotAvailable
    case errSecDataNotModifiable:
      self = .secDataNotModifiable
    case errSecCreateChainFailed:
      self = .secCreateChainFailed
    case errSecInvalidPrefsDomain:
      self = .secInvalidPrefsDomain
    case errSecInDarkWake:
      self = .secInDarkWake
    case errSecACLNotSimple:
      self = .secACLNotSimple
    case errSecPolicyNotFound:
      self = .secPolicyNotFound
    case errSecInvalidTrustSetting:
      self = .secInvalidTrustSetting
    case errSecNoAccessForItem:
      self = .secNoAccessForItem
    case errSecInvalidOwnerEdit:
      self = .secInvalidOwnerEdit
    case errSecTrustNotAvailable:
      self = .secTrustNotAvailable
    case errSecUnsupportedFormat:
      self = .secUnsupportedFormat
    case errSecUnknownFormat:
      self = .secUnknownFormat
    case errSecKeyIsSensitive:
      self = .secKeyIsSensitive
    case errSecMultiplePrivKeys:
      self = .secMultiplePrivKeys
    case errSecPassphraseRequired:
      self = .secPassphraseRequired
    case errSecInvalidPasswordRef:
      self = .secInvalidPasswordRef
    case errSecInvalidTrustSettings:
      self = .secInvalidTrustSettings
    case errSecNoTrustSettings:
      self = .secNoTrustSettings
    case errSecPkcs12VerifyFailure:
      self = .secPkcs12VerifyFailure
    case errSecNotSigner:
      self = .secNotSigner
    case errSecDecode:
      self = .secDecode
    case errSecServiceNotAvailable:
      self = .secServiceNotAvailable
    case errSecInsufficientClientID:
      self = .secInsufficientClientID
    case errSecDeviceReset:
      self = .secDeviceReset
    case errSecDeviceFailed:
      self = .secDeviceFailed
    case errSecAppleAddAppACLSubject:
      self = .secAppleAddAppACLSubject
    case errSecApplePublicKeyIncomplete:
      self = .secApplePublicKeyIncomplete
    case errSecAppleSignatureMismatch:
      self = .secAppleSignatureMismatch
    case errSecAppleInvalidKeyStartDate:
      self = .secAppleInvalidKeyStartDate
    case errSecAppleInvalidKeyEndDate:
      self = .secAppleInvalidKeyEndDate
    case errSecConversionError:
      self = .secConversionError
    case errSecAppleSSLv2Rollback:
      self = .secAppleSSLv2Rollback
    case errSecQuotaExceeded:
      self = .secQuotaExceeded
    case errSecFileTooBig:
      self = .secFileTooBig
    case errSecInvalidDatabaseBlob:
      self = .secInvalidDatabaseBlob
    case errSecInvalidKeyBlob:
      self = .secInvalidKeyBlob
    case errSecIncompatibleDatabaseBlob:
      self = .secIncompatibleDatabaseBlob
    case errSecIncompatibleKeyBlob:
      self = .secIncompatibleKeyBlob
    case errSecHostNameMismatch:
      self = .secHostNameMismatch
    case errSecUnknownCriticalExtensionFlag:
      self = .secUnknownCriticalExtensionFlag
    case errSecNoBasicConstraints:
      self = .secNoBasicConstraints
    case errSecNoBasicConstraintsCA:
      self = .secNoBasicConstraintsCA
    case errSecInvalidAuthorityKeyID:
      self = .secInvalidAuthorityKeyID
    case errSecInvalidSubjectKeyID:
      self = .secInvalidSubjectKeyID
    case errSecInvalidKeyUsageForPolicy:
      self = .secInvalidKeyUsageForPolicy
    case errSecInvalidExtendedKeyUsage:
      self = .secInvalidExtendedKeyUsage
    case errSecInvalidIDLinkage:
      self = .secInvalidIDLinkage
    case errSecPathLengthConstraintExceeded:
      self = .secPathLengthConstraintExceeded
    case errSecInvalidRoot:
      self = .secInvalidRoot
    case errSecCRLExpired:
      self = .secCRLExpired
    case errSecCRLNotValidYet:
      self = .secCRLNotValidYet
    case errSecCRLNotFound:
      self = .secCRLNotFound
    case errSecCRLServerDown:
      self = .secCRLServerDown
    case errSecCRLBadURI:
      self = .secCRLBadURI
    case errSecUnknownCertExtension:
      self = .secUnknownCertExtension
    case errSecUnknownCRLExtension:
      self = .secUnknownCRLExtension
    case errSecCRLNotTrusted:
      self = .secCRLNotTrusted
    case errSecCRLPolicyFailed:
      self = .secCRLPolicyFailed
    case errSecIDPFailure:
      self = .secIDPFailure
    case errSecSMIMEEmailAddressesNotFound:
      self = .secSMIMEEmailAddressesNotFound
    case errSecSMIMEBadExtendedKeyUsage:
      self = .secSMIMEBadExtendedKeyUsage
    case errSecSMIMEBadKeyUsage:
      self = .secSMIMEBadKeyUsage
    case errSecSMIMEKeyUsageNotCritical:
      self = .secSMIMEKeyUsageNotCritical
    case errSecSMIMENoEmailAddress:
      self = .secSMIMENoEmailAddress
    case errSecSMIMESubjAltNameNotCritical:
      self = .secSMIMESubjAltNameNotCritical
    case errSecSSLBadExtendedKeyUsage:
      self = .secSSLBadExtendedKeyUsage
    case errSecOCSPBadResponse:
      self = .secOCSPBadResponse
    case errSecOCSPBadRequest:
      self = .secOCSPBadRequest
    case errSecOCSPUnavailable:
      self = .secOCSPUnavailable
    case errSecOCSPStatusUnrecognized:
      self = .secOCSPStatusUnrecognized
    case errSecEndOfData:
      self = .secEndOfData
    case errSecIncompleteCertRevocationCheck:
      self = .secIncompleteCertRevocationCheck
    case errSecNetworkFailure:
      self = .secNetworkFailure
    case errSecOCSPNotTrustedToAnchor:
      self = .secOCSPNotTrustedToAnchor
    case errSecRecordModified:
      self = .secRecordModified
    case errSecOCSPSignatureError:
      self = .secOCSPSignatureError
    case errSecOCSPNoSigner:
      self = .secOCSPNoSigner
    case errSecOCSPResponderMalformedReq:
      self = .secOCSPResponderMalformedReq
    case errSecOCSPResponderInternalError:
      self = .secOCSPResponderInternalError
    case errSecOCSPResponderTryLater:
      self = .secOCSPResponderTryLater
    case errSecOCSPResponderSignatureRequired:
      self = .secOCSPResponderSignatureRequired
    case errSecOCSPResponderUnauthorized:
      self = .secOCSPResponderUnauthorized
    case errSecOCSPResponseNonceMismatch:
      self = .secOCSPResponseNonceMismatch
    case errSecCodeSigningBadCertChainLength:
      self = .secCodeSigningBadCertChainLength
    case errSecCodeSigningNoBasicConstraints:
      self = .secCodeSigningNoBasicConstraints
    case errSecCodeSigningBadPathLengthConstraint:
      self = .secCodeSigningBadPathLengthConstraint
    case errSecCodeSigningNoExtendedKeyUsage:
      self = .secCodeSigningNoExtendedKeyUsage
    case errSecCodeSigningDevelopment:
      self = .secCodeSigningDevelopment
    case errSecResourceSignBadCertChainLength:
      self = .secResourceSignBadCertChainLength
    case errSecResourceSignBadExtKeyUsage:
      self = .secResourceSignBadExtKeyUsage
    case errSecTrustSettingDeny:
      self = .secTrustSettingDeny
    case errSecInvalidSubjectName:
      self = .secInvalidSubjectName
    case errSecUnknownQualifiedCertStatement:
      self = .secUnknownQualifiedCertStatement
    case errSecMobileMeRequestQueued:
      self = .secMobileMeRequestQueued
    case errSecMobileMeRequestRedirected:
      self = .secMobileMeRequestRedirected
    case errSecMobileMeServerError:
      self = .secMobileMeServerError
    case errSecMobileMeServerNotAvailable:
      self = .secMobileMeServerNotAvailable
    case errSecMobileMeServerAlreadyExists:
      self = .secMobileMeServerAlreadyExists
    case errSecMobileMeServerServiceErr:
      self = .secMobileMeServerServiceErr
    case errSecMobileMeRequestAlreadyPending:
      self = .secMobileMeRequestAlreadyPending
    case errSecMobileMeNoRequestPending:
      self = .secMobileMeNoRequestPending
    case errSecMobileMeCSRVerifyFailure:
      self = .secMobileMeCSRVerifyFailure
    case errSecMobileMeFailedConsistencyCheck:
      self = .secMobileMeFailedConsistencyCheck
    case errSecNotInitialized:
      self = .secNotInitialized
    case errSecInvalidHandleUsage:
      self = .secInvalidHandleUsage
    case errSecPVCReferentNotFound:
      self = .secPVCReferentNotFound
    case errSecFunctionIntegrityFail:
      self = .secFunctionIntegrityFail
    case errSecInternalError:
      self = .secInternalError
    case errSecMemoryError:
      self = .secMemoryError
    case errSecInvalidData:
      self = .secInvalidData
    case errSecMDSError:
      self = .secMDSError
    case errSecInvalidPointer:
      self = .secInvalidPointer
    case errSecSelfCheckFailed:
      self = .secSelfCheckFailed
    case errSecFunctionFailed:
      self = .secFunctionFailed
    case errSecModuleManifestVerifyFailed:
      self = .secModuleManifestVerifyFailed
    case errSecInvalidGUID:
      self = .secInvalidGUID
    case errSecInvalidHandle:
      self = .secInvalidHandle
    case errSecInvalidDBList:
      self = .secInvalidDBList
    case errSecInvalidPassthroughID:
      self = .secInvalidPassthroughID
    case errSecInvalidNetworkAddress:
      self = .secInvalidNetworkAddress
    case errSecCRLAlreadySigned:
      self = .secCRLAlreadySigned
    case errSecInvalidNumberOfFields:
      self = .secInvalidNumberOfFields
    case errSecVerificationFailure:
      self = .secVerificationFailure
    case errSecUnknownTag:
      self = .secUnknownTag
    case errSecInvalidSignature:
      self = .secInvalidSignature
    case errSecInvalidName:
      self = .secInvalidName
    case errSecInvalidCertificateRef:
      self = .secInvalidCertificateRef
    case errSecInvalidCertificateGroup:
      self = .secInvalidCertificateGroup
    case errSecTagNotFound:
      self = .secTagNotFound
    case errSecInvalidQuery:
      self = .secInvalidQuery
    case errSecInvalidValue:
      self = .secInvalidValue
    case errSecCallbackFailed:
      self = .secCallbackFailed
    case errSecACLDeleteFailed:
      self = .secACLDeleteFailed
    case errSecACLReplaceFailed:
      self = .secACLReplaceFailed
    case errSecACLAddFailed:
      self = .secACLAddFailed
    case errSecACLChangeFailed:
      self = .secACLChangeFailed
    case errSecInvalidAccessCredentials:
      self = .secInvalidAccessCredentials
    case errSecInvalidRecord:
      self = .secInvalidRecord
    case errSecInvalidACL:
      self = .secInvalidACL
    case errSecInvalidSampleValue:
      self = .secInvalidSampleValue
    case errSecIncompatibleVersion:
      self = .secIncompatibleVersion
    case errSecPrivilegeNotGranted:
      self = .secPrivilegeNotGranted
    case errSecInvalidScope:
      self = .secInvalidScope
    case errSecPVCAlreadyConfigured:
      self = .secPVCAlreadyConfigured
    case errSecInvalidPVC:
      self = .secInvalidPVC
    case errSecEMMLoadFailed:
      self = .secEMMLoadFailed
    case errSecEMMUnloadFailed:
      self = .secEMMUnloadFailed
    case errSecAddinLoadFailed:
      self = .secAddinLoadFailed
    case errSecInvalidKeyRef:
      self = .secInvalidKeyRef
    case errSecInvalidKeyHierarchy:
      self = .secInvalidKeyHierarchy
    case errSecAddinUnloadFailed:
      self = .secAddinUnloadFailed
    case errSecLibraryReferenceNotFound:
      self = .secLibraryReferenceNotFound
    case errSecInvalidAddinFunctionTable:
      self = .secInvalidAddinFunctionTable
    case errSecInvalidServiceMask:
      self = .secInvalidServiceMask
    case errSecModuleNotLoaded:
      self = .secModuleNotLoaded
    case errSecInvalidSubServiceID:
      self = .secInvalidSubServiceID
    case errSecAttributeNotInContext:
      self = .secAttributeNotInContext
    case errSecModuleManagerInitializeFailed:
      self = .secModuleManagerInitializeFailed
    case errSecModuleManagerNotFound:
      self = .secModuleManagerNotFound
    case errSecEventNotificationCallbackNotFound:
      self = .secEventNotificationCallbackNotFound
    case errSecInputLengthError:
      self = .secInputLengthError
    case errSecOutputLengthError:
      self = .secOutputLengthError
    case errSecPrivilegeNotSupported:
      self = .secPrivilegeNotSupported
    case errSecDeviceError:
      self = .secDeviceError
    case errSecAttachHandleBusy:
      self = .secAttachHandleBusy
    case errSecNotLoggedIn:
      self = .secNotLoggedIn
    case errSecAlgorithmMismatch:
      self = .secAlgorithmMismatch
    case errSecKeyUsageIncorrect:
      self = .secKeyUsageIncorrect
    case errSecKeyBlobTypeIncorrect:
      self = .secKeyBlobTypeIncorrect
    case errSecKeyHeaderInconsistent:
      self = .secKeyHeaderInconsistent
    case errSecUnsupportedKeyFormat:
      self = .secUnsupportedKeyFormat
    case errSecUnsupportedKeySize:
      self = .secUnsupportedKeySize
    case errSecInvalidKeyUsageMask:
      self = .secInvalidKeyUsageMask
    case errSecUnsupportedKeyUsageMask:
      self = .secUnsupportedKeyUsageMask
    case errSecInvalidKeyAttributeMask:
      self = .secInvalidKeyAttributeMask
    case errSecUnsupportedKeyAttributeMask:
      self = .secUnsupportedKeyAttributeMask
    case errSecInvalidKeyLabel:
      self = .secInvalidKeyLabel
    case errSecUnsupportedKeyLabel:
      self = .secUnsupportedKeyLabel
    case errSecInvalidKeyFormat:
      self = .secInvalidKeyFormat
    case errSecUnsupportedVectorOfBuffers:
      self = .secUnsupportedVectorOfBuffers
    case errSecInvalidInputVector:
      self = .secInvalidInputVector
    case errSecInvalidOutputVector:
      self = .secInvalidOutputVector
    case errSecInvalidContext:
      self = .secInvalidContext
    case errSecInvalidAlgorithm:
      self = .secInvalidAlgorithm
    case errSecInvalidAttributeKey:
      self = .secInvalidAttributeKey
    case errSecMissingAttributeKey:
      self = .secMissingAttributeKey
    case errSecInvalidAttributeInitVector:
      self = .secInvalidAttributeInitVector
    case errSecMissingAttributeInitVector:
      self = .secMissingAttributeInitVector
    case errSecInvalidAttributeSalt:
      self = .secInvalidAttributeSalt
    case errSecMissingAttributeSalt:
      self = .secMissingAttributeSalt
    case errSecInvalidAttributePadding:
      self = .secInvalidAttributePadding
    case errSecMissingAttributePadding:
      self = .secMissingAttributePadding
    case errSecInvalidAttributeRandom:
      self = .secInvalidAttributeRandom
    case errSecMissingAttributeRandom:
      self = .secMissingAttributeRandom
    case errSecInvalidAttributeSeed:
      self = .secInvalidAttributeSeed
    case errSecMissingAttributeSeed:
      self = .secMissingAttributeSeed
    case errSecInvalidAttributePassphrase:
      self = .secInvalidAttributePassphrase
    case errSecMissingAttributePassphrase:
      self = .secMissingAttributePassphrase
    case errSecInvalidAttributeKeyLength:
      self = .secInvalidAttributeKeyLength
    case errSecMissingAttributeKeyLength:
      self = .secMissingAttributeKeyLength
    case errSecInvalidAttributeBlockSize:
      self = .secInvalidAttributeBlockSize
    case errSecMissingAttributeBlockSize:
      self = .secMissingAttributeBlockSize
    case errSecInvalidAttributeOutputSize:
      self = .secInvalidAttributeOutputSize
    case errSecMissingAttributeOutputSize:
      self = .secMissingAttributeOutputSize
    case errSecInvalidAttributeRounds:
      self = .secInvalidAttributeRounds
    case errSecMissingAttributeRounds:
      self = .secMissingAttributeRounds
    case errSecInvalidAlgorithmParms:
      self = .secInvalidAlgorithmParms
    case errSecMissingAlgorithmParms:
      self = .secMissingAlgorithmParms
    case errSecInvalidAttributeLabel:
      self = .secInvalidAttributeLabel
    case errSecMissingAttributeLabel:
      self = .secMissingAttributeLabel
    case errSecInvalidAttributeKeyType:
      self = .secInvalidAttributeKeyType
    case errSecMissingAttributeKeyType:
      self = .secMissingAttributeKeyType
    case errSecInvalidAttributeMode:
      self = .secInvalidAttributeMode
    case errSecMissingAttributeMode:
      self = .secMissingAttributeMode
    case errSecInvalidAttributeEffectiveBits:
      self = .secInvalidAttributeEffectiveBits
    case errSecMissingAttributeEffectiveBits:
      self = .secMissingAttributeEffectiveBits
    case errSecInvalidAttributeStartDate:
      self = .secInvalidAttributeStartDate
    case errSecMissingAttributeStartDate:
      self = .secMissingAttributeStartDate
    case errSecInvalidAttributeEndDate:
      self = .secInvalidAttributeEndDate
    case errSecMissingAttributeEndDate:
      self = .secMissingAttributeEndDate
    case errSecInvalidAttributeVersion:
      self = .secInvalidAttributeVersion
    case errSecMissingAttributeVersion:
      self = .secMissingAttributeVersion
    case errSecInvalidAttributePrime:
      self = .secInvalidAttributePrime
    case errSecMissingAttributePrime:
      self = .secMissingAttributePrime
    case errSecInvalidAttributeBase:
      self = .secInvalidAttributeBase
    case errSecMissingAttributeBase:
      self = .secMissingAttributeBase
    case errSecInvalidAttributeSubprime:
      self = .secInvalidAttributeSubprime
    case errSecMissingAttributeSubprime:
      self = .secMissingAttributeSubprime
    case errSecInvalidAttributeIterationCount:
      self = .secInvalidAttributeIterationCount
    case errSecMissingAttributeIterationCount:
      self = .secMissingAttributeIterationCount
    case errSecInvalidAttributeDLDBHandle:
      self = .secInvalidAttributeDLDBHandle
    case errSecMissingAttributeDLDBHandle:
      self = .secMissingAttributeDLDBHandle
    case errSecInvalidAttributeAccessCredentials:
      self = .secInvalidAttributeAccessCredentials
    case errSecMissingAttributeAccessCredentials:
      self = .secMissingAttributeAccessCredentials
    case errSecInvalidAttributePublicKeyFormat:
      self = .secInvalidAttributePublicKeyFormat
    case errSecMissingAttributePublicKeyFormat:
      self = .secMissingAttributePublicKeyFormat
    case errSecInvalidAttributePrivateKeyFormat:
      self = .secInvalidAttributePrivateKeyFormat
    case errSecMissingAttributePrivateKeyFormat:
      self = .secMissingAttributePrivateKeyFormat
    case errSecInvalidAttributeSymmetricKeyFormat:
      self = .secInvalidAttributeSymmetricKeyFormat
    case errSecMissingAttributeSymmetricKeyFormat:
      self = .secMissingAttributeSymmetricKeyFormat
    case errSecInvalidAttributeWrappedKeyFormat:
      self = .secInvalidAttributeWrappedKeyFormat
    case errSecMissingAttributeWrappedKeyFormat:
      self = .secMissingAttributeWrappedKeyFormat
    case errSecStagedOperationInProgress:
      self = .secStagedOperationInProgress
    case errSecStagedOperationNotStarted:
      self = .secStagedOperationNotStarted
    case errSecVerifyFailed:
      self = .secVerifyFailed
    case errSecQuerySizeUnknown:
      self = .secQuerySizeUnknown
    case errSecBlockSizeMismatch:
      self = .secBlockSizeMismatch
    case errSecPublicKeyInconsistent:
      self = .secPublicKeyInconsistent
    case errSecDeviceVerifyFailed:
      self = .secDeviceVerifyFailed
    case errSecInvalidLoginName:
      self = .secInvalidLoginName
    case errSecAlreadyLoggedIn:
      self = .secAlreadyLoggedIn
    case errSecInvalidDigestAlgorithm:
      self = .secInvalidDigestAlgorithm
    case errSecInvalidCRLGroup:
      self = .secInvalidCRLGroup
    case errSecCertificateCannotOperate:
      self = .secCertificateCannotOperate
    case errSecCertificateExpired:
      self = .secCertificateExpired
    case errSecCertificateNotValidYet:
      self = .secCertificateNotValidYet
    case errSecCertificateRevoked:
      self = .secCertificateRevoked
    case errSecCertificateSuspended:
      self = .secCertificateSuspended
    case errSecInsufficientCredentials:
      self = .secInsufficientCredentials
    case errSecInvalidAction:
      self = .secInvalidAction
    case errSecInvalidAuthority:
      self = .secInvalidAuthority
    case errSecVerifyActionFailed:
      self = .secVerifyActionFailed
    case errSecInvalidCertAuthority:
      self = .secInvalidCertAuthority
    case errSecInvalidCRLAuthority:
      self = .secInvalidCRLAuthority
    case errSecInvaldCRLAuthority:
      self = .secInvaldCRLAuthority
    case errSecInvalidCRLEncoding:
      self = .secInvalidCRLEncoding
    case errSecInvalidCRLType:
      self = .secInvalidCRLType
    case errSecInvalidCRL:
      self = .secInvalidCRL
    case errSecInvalidFormType:
      self = .secInvalidFormType
    case errSecInvalidID:
      self = .secInvalidID
    case errSecInvalidIdentifier:
      self = .secInvalidIdentifier
    case errSecInvalidIndex:
      self = .secInvalidIndex
    case errSecInvalidPolicyIdentifiers:
      self = .secInvalidPolicyIdentifiers
    case errSecInvalidTimeString:
      self = .secInvalidTimeString
    case errSecInvalidReason:
      self = .secInvalidReason
    case errSecInvalidRequestInputs:
      self = .secInvalidRequestInputs
    case errSecInvalidResponseVector:
      self = .secInvalidResponseVector
    case errSecInvalidStopOnPolicy:
      self = .secInvalidStopOnPolicy
    case errSecInvalidTuple:
      self = .secInvalidTuple
    case errSecMultipleValuesUnsupported:
      self = .secMultipleValuesUnsupported
    case errSecNotTrusted:
      self = .secNotTrusted
    case errSecNoDefaultAuthority:
      self = .secNoDefaultAuthority
    case errSecRejectedForm:
      self = .secRejectedForm
    case errSecRequestLost:
      self = .secRequestLost
    case errSecRequestRejected:
      self = .secRequestRejected
    case errSecUnsupportedAddressType:
      self = .secUnsupportedAddressType
    case errSecUnsupportedService:
      self = .secUnsupportedService
    case errSecInvalidTupleGroup:
      self = .secInvalidTupleGroup
    case errSecInvalidBaseACLs:
      self = .secInvalidBaseACLs
    case errSecInvalidTupleCredentials:
      self = .secInvalidTupleCredentials
    case errSecInvalidTupleCredendtials:
      self = .secInvalidTupleCredendtials
    case errSecInvalidEncoding:
      self = .secInvalidEncoding
    case errSecInvalidValidityPeriod:
      self = .secInvalidValidityPeriod
    case errSecInvalidRequestor:
      self = .secInvalidRequestor
    case errSecRequestDescriptor:
      self = .secRequestDescriptor
    case errSecInvalidBundleInfo:
      self = .secInvalidBundleInfo
    case errSecInvalidCRLIndex:
      self = .secInvalidCRLIndex
    case errSecNoFieldValues:
      self = .secNoFieldValues
    case errSecUnsupportedFieldFormat:
      self = .secUnsupportedFieldFormat
    case errSecUnsupportedIndexInfo:
      self = .secUnsupportedIndexInfo
    case errSecUnsupportedLocality:
      self = .secUnsupportedLocality
    case errSecUnsupportedNumAttributes:
      self = .secUnsupportedNumAttributes
    case errSecUnsupportedNumIndexes:
      self = .secUnsupportedNumIndexes
    case errSecUnsupportedNumRecordTypes:
      self = .secUnsupportedNumRecordTypes
    case errSecFieldSpecifiedMultiple:
      self = .secFieldSpecifiedMultiple
    case errSecIncompatibleFieldFormat:
      self = .secIncompatibleFieldFormat
    case errSecInvalidParsingModule:
      self = .secInvalidParsingModule
    case errSecDatabaseLocked:
      self = .secDatabaseLocked
    case errSecDatastoreIsOpen:
      self = .secDatastoreIsOpen
    case errSecMissingValue:
      self = .secMissingValue
    case errSecUnsupportedQueryLimits:
      self = .secUnsupportedQueryLimits
    case errSecUnsupportedNumSelectionPreds:
      self = .secUnsupportedNumSelectionPreds
    case errSecUnsupportedOperator:
      self = .secUnsupportedOperator
    case errSecInvalidDBLocation:
      self = .secInvalidDBLocation
    case errSecInvalidAccessRequest:
      self = .secInvalidAccessRequest
    case errSecInvalidIndexInfo:
      self = .secInvalidIndexInfo
    case errSecInvalidNewOwner:
      self = .secInvalidNewOwner
    case errSecInvalidModifyMode:
      self = .secInvalidModifyMode
    case errSecMissingRequiredExtension:
      self = .secMissingRequiredExtension
    case errSecExtendedKeyUsageNotCritical:
      self = .secExtendedKeyUsageNotCritical
    case errSecTimestampMissing:
      self = .secTimestampMissing
    case errSecTimestampInvalid:
      self = .secTimestampInvalid
    case errSecTimestampNotTrusted:
      self = .secTimestampNotTrusted
    case errSecTimestampServiceNotAvailable:
      self = .secTimestampServiceNotAvailable
    case errSecTimestampBadAlg:
      self = .secTimestampBadAlg
    case errSecTimestampBadRequest:
      self = .secTimestampBadRequest
    case errSecTimestampBadDataFormat:
      self = .secTimestampBadDataFormat
    case errSecTimestampTimeNotAvailable:
      self = .secTimestampTimeNotAvailable
    case errSecTimestampUnacceptedPolicy:
      self = .secTimestampUnacceptedPolicy
    case errSecTimestampUnacceptedExtension:
      self = .secTimestampUnacceptedExtension
    case errSecTimestampAddInfoNotAvailable:
      self = .secTimestampAddInfoNotAvailable
    case errSecTimestampSystemFailure:
      self = .secTimestampSystemFailure
    case errSecSigningTimeMissing:
      self = .secSigningTimeMissing
    case errSecTimestampRejection:
      self = .secTimestampRejection
    case errSecTimestampWaiting:
      self = .secTimestampWaiting
    case errSecTimestampRevocationWarning:
      self = .secTimestampRevocationWarning
    case errSecTimestampRevocationNotification:
      self = .secTimestampRevocationNotification
    case errSecCertificatePolicyNotAllowed:
      self = .secCertificatePolicyNotAllowed
    case errSecCertificateNameNotAllowed:
      self = .secCertificateNameNotAllowed
    case errSecCertificateValidityPeriodTooLong:
      self = .secCertificateValidityPeriodTooLong
    case errSecCertificateIsCA:
      self = .secCertificateIsCA
    case errSecCertificateDuplicateExtension:
      self = .secCertificateDuplicateExtension
    case errSSLProtocol:
      self = .sslProtocol
    case errSSLNegotiation:
      self = .sslNegotiation
    case errSSLFatalAlert:
      self = .sslFatalAlert
    case errSSLWouldBlock:
      self = .sslWouldBlock
    case errSSLSessionNotFound:
      self = .sslSessionNotFound
    case errSSLClosedGraceful:
      self = .sslClosedGraceful
    case errSSLClosedAbort:
      self = .sslClosedAbort
    case errSSLXCertChainInvalid:
      self = .sslXCertChainInvalid
    case errSSLBadCert:
      self = .sslBadCert
    case errSSLCrypto:
      self = .sslCrypto
    case errSSLInternal:
      self = .sslInternal
    case errSSLModuleAttach:
      self = .sslModuleAttach
    case errSSLUnknownRootCert:
      self = .sslUnknownRootCert
    case errSSLNoRootCert:
      self = .sslNoRootCert
    case errSSLCertExpired:
      self = .sslCertExpired
    case errSSLCertNotYetValid:
      self = .sslCertNotYetValid
    case errSSLClosedNoNotify:
      self = .sslClosedNoNotify
    case errSSLBufferOverflow:
      self = .sslBufferOverflow
    case errSSLBadCipherSuite:
      self = .sslBadCipherSuite
    case errSSLPeerUnexpectedMsg:
      self = .sslPeerUnexpectedMsg
    case errSSLPeerBadRecordMac:
      self = .sslPeerBadRecordMac
    case errSSLPeerDecryptionFail:
      self = .sslPeerDecryptionFail
    case errSSLPeerRecordOverflow:
      self = .sslPeerRecordOverflow
    case errSSLPeerDecompressFail:
      self = .sslPeerDecompressFail
    case errSSLPeerHandshakeFail:
      self = .sslPeerHandshakeFail
    case errSSLPeerBadCert:
      self = .sslPeerBadCert
    case errSSLPeerUnsupportedCert:
      self = .sslPeerUnsupportedCert
    case errSSLPeerCertRevoked:
      self = .sslPeerCertRevoked
    case errSSLPeerCertExpired:
      self = .sslPeerCertExpired
    case errSSLPeerCertUnknown:
      self = .sslPeerCertUnknown
    case errSSLIllegalParam:
      self = .sslIllegalParam
    case errSSLPeerUnknownCA:
      self = .sslPeerUnknownCA
    case errSSLPeerAccessDenied:
      self = .sslPeerAccessDenied
    case errSSLPeerDecodeError:
      self = .sslPeerDecodeError
    case errSSLPeerDecryptError:
      self = .sslPeerDecryptError
    case errSSLPeerExportRestriction:
      self = .sslPeerExportRestriction
    case errSSLPeerProtocolVersion:
      self = .sslPeerProtocolVersion
    case errSSLPeerInsufficientSecurity:
      self = .sslPeerInsufficientSecurity
    case errSSLPeerInternalError:
      self = .sslPeerInternalError
    case errSSLPeerUserCancelled:
      self = .sslPeerUserCancelled
    case errSSLPeerNoRenegotiation:
      self = .sslPeerNoRenegotiation
    case errSSLPeerAuthCompleted:
      self = .sslPeerAuthCompleted
    case errSSLClientCertRequested:
      self = .sslClientCertRequested
    case errSSLHostNameMismatch:
      self = .sslHostNameMismatch
    case errSSLConnectionRefused:
      self = .sslConnectionRefused
    case errSSLDecryptionFail:
      self = .sslDecryptionFail
    case errSSLBadRecordMac:
      self = .sslBadRecordMac
    case errSSLRecordOverflow:
      self = .sslRecordOverflow
    case errSSLBadConfiguration:
      self = .sslBadConfiguration
    case errSSLUnexpectedRecord:
      self = .sslUnexpectedRecord
    case errSSLWeakPeerEphemeralDHKey:
      self = .sslWeakPeerEphemeralDHKey
    case errSSLClientHelloReceived:
      self = .sslClientHelloReceived
    case errSSLTransportReset:
      self = .sslTransportReset
    case errSSLNetworkTimeout:
      self = .sslNetworkTimeout
    case errSSLConfigurationFailed:
      self = .sslConfigurationFailed
    case errSSLUnsupportedExtension:
      self = .sslUnsupportedExtension
    case errSSLUnexpectedMessage:
      self = .sslUnexpectedMessage
    case errSSLDecompressFail:
      self = .sslDecompressFail
    case errSSLHandshakeFail:
      self = .sslHandshakeFail
    case errSSLDecodeError:
      self = .sslDecodeError
    case errSSLInappropriateFallback:
      self = .sslInappropriateFallback
    case errSSLMissingExtension:
      self = .sslMissingExtension
    case errSSLBadCertificateStatusResponse:
      self = .sslBadCertificateStatusResponse
    case errSSLCertificateRequired:
      self = .sslCertificateRequired
    case errSSLUnknownPSKIdentity:
      self = .sslUnknownPSKIdentity
    case errSSLUnrecognizedName:
      self = .sslUnrecognizedName
    case errSSLATSViolation:
      self = .sslATSViolation
    case errSSLATSMinimumVersionViolation:
      self = .sslATSMinimumVersionViolation
    case errSSLATSCiphersuiteViolation:
      self = .sslATSCiphersuiteViolation
    case errSSLATSMinimumKeySizeViolation:
      self = .sslATSMinimumKeySizeViolation
    case errSSLATSLeafCertificateHashAlgorithmViolation:
      self = .sslATSLeafCertificateHashAlgorithmViolation
    case errSSLATSCertificateHashAlgorithmViolation:
      self = .sslATSCertificateHashAlgorithmViolation
    case errSSLATSCertificateTrustViolation:
      self = .sslATSCertificateTrustViolation
    case errSSLEarlyDataRejected:
      self = .sslEarlyDataRejected
    default:
      fatalError()
    }
  }
}
