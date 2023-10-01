import { Certificate } from "pkijs";
import { DecodedNotificationPayload, JWSRenewalInfo, JWSRenewalInfoDecodedPayload, JWSTransaction, JWSTransactionDecodedPayload } from "./Models";
export declare function decodeTransactions(signedTransactions: JWSTransaction[], rootCertFingerprint?: string): Promise<JWSTransactionDecodedPayload[]>;
export declare function decodeTransaction(transaction: JWSTransaction, rootCertFingerprint?: string): Promise<JWSTransactionDecodedPayload>;
export declare function decodeRenewalInfo(info: JWSRenewalInfo, rootCertFingerprint?: string): Promise<JWSRenewalInfoDecodedPayload>;
export declare function decodeNotificationPayload(payload: string, rootCertFingerprint?: string): Promise<DecodedNotificationPayload>;
/**
 * Parses a certificate from a BufferSource.
 * @param source The BufferSource to parse.
 * @returns An array of Certificates.
 */
export declare function parseCertificate(source: BufferSource): Certificate[];
