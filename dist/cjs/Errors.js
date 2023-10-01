"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificateValidationError = exports.AppStoreError = void 0;
class AppStoreError extends Error {
    constructor(errorCode, errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
        this.isRetryable = AppStoreError.RETRYABLE_ERRORS.includes(errorCode);
        this.isRateLimitExceeded = errorCode === 4290000;
    }
}
exports.AppStoreError = AppStoreError;
// The following errors indicate that the request can be tried again.
// See https://developer.apple.com/documentation/appstoreserverapi/error_codes
// for a list of all errors.
AppStoreError.RETRYABLE_ERRORS = [
    4040002,
    4040004,
    5000001,
    4040006 // OriginalTransactionIdNotFoundRetryableError
];
class CertificateValidationError extends Error {
    constructor(certificates) {
        super("Certificate validation failed");
        this.certificates = certificates;
    }
}
exports.CertificateValidationError = CertificateValidationError;
