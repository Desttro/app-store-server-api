"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseCertificate = exports.decodeNotificationPayload = exports.decodeRenewalInfo = exports.decodeTransaction = exports.decodeTransactions = void 0;
const jose = __importStar(require("jose"));
const pkijs_1 = require("pkijs");
const pvtsutils_1 = require("pvtsutils");
const pvtsutils_2 = require("pvtsutils");
const pvutils_1 = require("pvutils");
const AppleRootCertificate_1 = require("./AppleRootCertificate");
const Errors_1 = require("./Errors");
async function decodeTransactions(signedTransactions, rootCertFingerprint) {
    return Promise.all(signedTransactions.map((transaction) => decodeJWS(transaction, rootCertFingerprint)));
}
exports.decodeTransactions = decodeTransactions;
async function decodeTransaction(transaction, rootCertFingerprint) {
    return decodeJWS(transaction, rootCertFingerprint);
}
exports.decodeTransaction = decodeTransaction;
async function decodeRenewalInfo(info, rootCertFingerprint) {
    return decodeJWS(info, rootCertFingerprint);
}
exports.decodeRenewalInfo = decodeRenewalInfo;
async function decodeNotificationPayload(payload, rootCertFingerprint) {
    return decodeJWS(payload, rootCertFingerprint);
}
exports.decodeNotificationPayload = decodeNotificationPayload;
// Compute the SHA-256 hash using the Web Cryptography API
async function computeSHA256(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
    return new Uint8Array(hashBuffer);
}
// Convert the hash to colon-separated hexadecimal
function bufferToColonSeparatedHex(buffer) {
    return Array.prototype.map
        .call(buffer, (byte) => 
    // biome-ignore lint/style/useTemplate: use of template literals in this context doesn't make the code significantly clearer.
    ("00" + byte.toString(16))
        .slice(-2)
        .toUpperCase())
        .join(":");
}
/**
 * Decodes a PEM (Privacy-Enhanced Mail) string into an array of ArrayBuffers.
 * @param pem The PEM string to decode.
 * @param tag The tag to use for the regular expression pattern. Defaults to "[A-Z0-9 ]+".
 * @returns An array of ArrayBuffers.
 */
function decodePEM(pem, tag = "[A-Z0-9 ]+") {
    // Create a regular expression pattern to match the PEM string.
    const pattern = new RegExp(`-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`, "g");
    const res = [];
    let matches = null;
    // Loop through the matches in the PEM string.
    // biome-ignore lint/suspicious/noAssignInExpressions: This is the only way to loop through the matches.
    while ((matches = pattern.exec(pem))) {
        // Remove carriage returns and newlines from the base64 string.
        const base64 = matches[1].replace(/\r/g, "").replace(/\n/g, "");
        // Convert the base64 string to an ArrayBuffer and add it to the result array.
        res.push(pvtsutils_2.Convert.FromBase64(base64));
    }
    // Return the result array.
    return res;
}
/**
 * Parses a certificate from a BufferSource.
 * @param source The BufferSource to parse.
 * @returns An array of Certificates.
 */
function parseCertificate(source) {
    const buffers = [];
    // Convert the BufferSource to an ArrayBuffer.
    const buffer = pvtsutils_1.BufferSourceConverter.toArrayBuffer(source);
    // Convert the ArrayBuffer to a binary string.
    const pem = pvtsutils_2.Convert.ToBinary(buffer);
    // If the binary string is a PEM string, decode it. Otherwise, use the original ArrayBuffer.
    if (/----BEGIN CERTIFICATE-----/.test(pem)) {
        buffers.push(...decodePEM(pem, "CERTIFICATE"));
    }
    else {
        buffers.push(buffer);
    }
    const res = [];
    // Convert each ArrayBuffer in the array to a Certificate and add it to the result array.
    for (const item of buffers) {
        res.push(pkijs_1.Certificate.fromBER(item));
    }
    // Return the result array.
    return res;
}
exports.parseCertificate = parseCertificate;
/**
 * Decodes and verifies an object signed by the App Store according to JWS.
 * See: https://developer.apple.com/documentation/appstoreserverapi/jwstransaction
 * @param token JWS token
 * @param rootCertFingerprint Root certificate to validate against. Defaults to Apple's G3 CA but can be overriden for testing purposes.
 */
async function decodeJWS(token, rootCertFingerprint = AppleRootCertificate_1.APPLE_ROOT_CA_G3_FINGERPRINT) {
    // Extracts the key used to sign the JWS from the header of the token
    const getKey = async (protectedHeader, _token) => {
        // RC 7515 stipulates that the key used to sign the JWS must be the first in the chain.
        // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
        var _a, _b;
        // jose will not import the certificate unless it is in a proper PKCS8 format.
        const certs = (_b = (_a = protectedHeader.x5c) === null || _a === void 0 ? void 0 : _a.map((c) => `-----BEGIN CERTIFICATE-----\n${c}\n-----END CERTIFICATE-----`)) !== null && _b !== void 0 ? _b : [];
        await validateCertificates(certs, rootCertFingerprint);
        return jose.importX509(certs[0], "ES256");
    };
    const { payload } = await jose.compactVerify(token, getKey);
    const decoded = new TextDecoder().decode(payload);
    const json = JSON.parse(decoded);
    return json;
}
/**
 * Validates a certificate chain provided in the x5c field of a decoded header of a JWS.
 * The certificates must be valid and have been signed by the provided
 * @param certificates A chain of certificates
 * @param rootCertFingerprint Expected SHA256 signature of the root certificate
 * @throws {CertificateValidationError} if any of the validation checks fail
 */
async function validateCertificates(certificates, rootCertFingerprint) {
    // If no certificates are provided, throw an error
    if (certificates.length === 0)
        throw new Errors_1.CertificateValidationError([]);
    // put certificates to ArrayBuffer and run parseCertificate function
    const x509certs = parseCertificate((0, pvutils_1.stringToArrayBuffer)(certificates.join("\n")));
    // Assuming the last certificate is the root
    const rootCa = x509certs[x509certs.length - 1];
    const intermediateCa = x509certs[1];
    const leafCert = x509certs[0];
    // Validate the certificate chain
    const chainEngine = new pkijs_1.CertificateChainValidationEngine({
        certs: [rootCa, intermediateCa, leafCert],
        checkDate: new Date(),
        trustedCerts: [rootCa],
    });
    const chain = await chainEngine.verify();
    // If the chain result is invalid, throw an error
    if (chain.result === false)
        throw new Errors_1.CertificateValidationError(certificates);
    // Convert the certificate back to its DER form
    const rootCaArrayBuffer = rootCa.toSchema(true).toBER(false);
    // Compute and set the fingerprint
    const hashArray = await computeSHA256(rootCaArrayBuffer);
    const rootCaFingerprint = bufferToColonSeparatedHex(hashArray);
    // Ensure that the last certificate in the chain is the expected root CA.
    if (rootCaFingerprint !== rootCertFingerprint) {
        throw new Errors_1.CertificateValidationError(certificates);
    }
}
