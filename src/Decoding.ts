import * as jose from "jose";
import { Certificate, CertificateChainValidationEngine } from "pkijs";
import { BufferSourceConverter } from "pvtsutils";
import { Convert } from "pvtsutils";
import { stringToArrayBuffer } from "pvutils";

import { APPLE_ROOT_CA_G3_FINGERPRINT } from "./AppleRootCertificate";
import { CertificateValidationError } from "./Errors";
import {
	DecodedNotificationPayload,
	JWSRenewalInfo,
	JWSRenewalInfoDecodedPayload,
	JWSTransaction,
	JWSTransactionDecodedPayload,
} from "./Models";

export async function decodeTransactions(
	signedTransactions: JWSTransaction[],
	rootCertFingerprint?: string,
): Promise<JWSTransactionDecodedPayload[]> {
	return Promise.all(
		signedTransactions.map((transaction) =>
			decodeJWS(transaction, rootCertFingerprint),
		),
	);
}

export async function decodeTransaction(
	transaction: JWSTransaction,
	rootCertFingerprint?: string,
): Promise<JWSTransactionDecodedPayload> {
	return decodeJWS(transaction, rootCertFingerprint);
}

export async function decodeRenewalInfo(
	info: JWSRenewalInfo,
	rootCertFingerprint?: string,
): Promise<JWSRenewalInfoDecodedPayload> {
	return decodeJWS(info, rootCertFingerprint);
}

export async function decodeNotificationPayload(
	payload: string,
	rootCertFingerprint?: string,
): Promise<DecodedNotificationPayload> {
	return decodeJWS(payload, rootCertFingerprint);
}

// Compute the SHA-256 hash using the Web Cryptography API
async function computeSHA256(arrayBuffer: ArrayBuffer) {
	const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
	return new Uint8Array(hashBuffer);
}

// Convert the hash to colon-separated hexadecimal
function bufferToColonSeparatedHex(buffer: Uint8Array) {
	return Array.prototype.map
		.call(buffer, (byte) =>
			// biome-ignore lint/style/useTemplate: use of template literals in this context doesn't make the code significantly clearer.
			("00" + byte.toString(16))
				.slice(-2)
				.toUpperCase(),
		)
		.join(":");
}

/**
 * Decodes a PEM (Privacy-Enhanced Mail) string into an array of ArrayBuffers.
 * @param pem The PEM string to decode.
 * @param tag The tag to use for the regular expression pattern. Defaults to "[A-Z0-9 ]+".
 * @returns An array of ArrayBuffers.
 */
function decodePEM(pem: string, tag = "[A-Z0-9 ]+"): ArrayBuffer[] {
	// Create a regular expression pattern to match the PEM string.
	const pattern = new RegExp(
		`-{5}BEGIN ${tag}-{5}([a-zA-Z0-9=+\\/\\n\\r]+)-{5}END ${tag}-{5}`,
		"g",
	);

	const res: ArrayBuffer[] = [];
	let matches: RegExpExecArray | null = null;
	// Loop through the matches in the PEM string.
	// biome-ignore lint/suspicious/noAssignInExpressions: This is the only way to loop through the matches.
	while ((matches = pattern.exec(pem))) {
		// Remove carriage returns and newlines from the base64 string.
		const base64 = matches[1].replace(/\r/g, "").replace(/\n/g, "");
		// Convert the base64 string to an ArrayBuffer and add it to the result array.
		res.push(Convert.FromBase64(base64));
	}

	// Return the result array.
	return res;
}

/**
 * Parses a certificate from a BufferSource.
 * @param source The BufferSource to parse.
 * @returns An array of Certificates.
 */
export function parseCertificate(source: BufferSource): Certificate[] {
	const buffers: ArrayBuffer[] = [];

	// Convert the BufferSource to an ArrayBuffer.
	const buffer = BufferSourceConverter.toArrayBuffer(source);
	// Convert the ArrayBuffer to a binary string.
	const pem = Convert.ToBinary(buffer);
	// If the binary string is a PEM string, decode it. Otherwise, use the original ArrayBuffer.
	if (/----BEGIN CERTIFICATE-----/.test(pem)) {
		buffers.push(...decodePEM(pem, "CERTIFICATE"));
	} else {
		buffers.push(buffer);
	}

	const res: Certificate[] = [];
	// Convert each ArrayBuffer in the array to a Certificate and add it to the result array.
	for (const item of buffers) {
		res.push(Certificate.fromBER(item));
	}

	// Return the result array.
	return res;
}

/**
 * Decodes and verifies an object signed by the App Store according to JWS.
 * See: https://developer.apple.com/documentation/appstoreserverapi/jwstransaction
 * @param token JWS token
 * @param rootCertFingerprint Root certificate to validate against. Defaults to Apple's G3 CA but can be overriden for testing purposes.
 */
async function decodeJWS(
	token: string,
	rootCertFingerprint: string = APPLE_ROOT_CA_G3_FINGERPRINT,
): Promise<any> {
	// Extracts the key used to sign the JWS from the header of the token
	const getKey: jose.CompactVerifyGetKey = async (protectedHeader, _token) => {
		// RC 7515 stipulates that the key used to sign the JWS must be the first in the chain.
		// https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6

		// jose will not import the certificate unless it is in a proper PKCS8 format.
		const certs =
			protectedHeader.x5c?.map(
				(c) => `-----BEGIN CERTIFICATE-----\n${c}\n-----END CERTIFICATE-----`,
			) ?? [];

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
async function validateCertificates(
	certificates: string[],
	rootCertFingerprint: string,
) {
	// If no certificates are provided, throw an error
	if (certificates.length === 0) throw new CertificateValidationError([]);

	// put certificates to ArrayBuffer and run parseCertificate function
	const x509certs = parseCertificate(
		stringToArrayBuffer(certificates.join("\n")),
	);

	// Assuming the last certificate is the root
	const rootCa = x509certs[x509certs.length - 1];
	const intermediateCa = x509certs[1];
	const leafCert = x509certs[0];

	// Validate the certificate chain
	const chainEngine = new CertificateChainValidationEngine({
		certs: [rootCa, intermediateCa, leafCert],
		checkDate: new Date(),
		trustedCerts: [rootCa],
	});

	const chain = await chainEngine.verify();

	// If the chain result is invalid, throw an error
	if (chain.result === false)
		throw new CertificateValidationError(certificates);

	// Convert the certificate back to its DER form
	const rootCaArrayBuffer = rootCa.toSchema(true).toBER(false);

	// Compute and set the fingerprint
	const hashArray = await computeSHA256(rootCaArrayBuffer);
	const rootCaFingerprint = bufferToColonSeparatedHex(hashArray);

	// Ensure that the last certificate in the chain is the expected root CA.
	if (rootCaFingerprint !== rootCertFingerprint) {
		throw new CertificateValidationError(certificates);
	}
}
