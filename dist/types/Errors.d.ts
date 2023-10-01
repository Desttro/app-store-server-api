export declare class AppStoreError extends Error {
    static readonly RETRYABLE_ERRORS: number[];
    errorCode: number;
    isRetryable: boolean;
    isRateLimitExceeded: boolean;
    constructor(errorCode: number, errorMessage: string);
}
export declare class CertificateValidationError extends Error {
    certificates: string[];
    constructor(certificates: string[]);
}
