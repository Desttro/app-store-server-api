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
exports.AppStoreServerAPI = void 0;
const jose = __importStar(require("jose"));
const uuid_1 = require("uuid");
const Errors_1 = require("./Errors");
const Models_1 = require("./Models");
class AppStoreServerAPI {
    /**
     * @param key the key downloaded from App Store Connect in PEM-encoded PKCS8 format.
     * @param keyId the id of the key, retrieved from App Store Connect
     * @param issuerId your issuer ID, retrieved from App Store Connect
     * @param bundleId bundle ID of your app
     */
    constructor(key, keyId, issuerId, bundleId, environment = Models_1.Environment.Production) {
        this.tokenExpiry = new Date(0);
        this.key = jose.importPKCS8(key, "ES256");
        this.keyId = keyId;
        this.issuerId = issuerId;
        this.bundleId = bundleId;
        this.environment = environment;
        if (environment === Models_1.Environment.Sandbox) {
            this.baseUrl = "https://api.storekit-sandbox.itunes.apple.com";
        }
        else {
            this.baseUrl = "https://api.storekit.itunes.apple.com";
        }
    }
    // API Endpoints
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history
     */
    async getTransactionHistory(transactionId, query = {}) {
        const path = this.addQuery(`/inApps/v1/history/${transactionId}`, {
            ...query,
        });
        return this.makeRequest("GET", path);
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_transaction_info
     */
    async getTransactionInfo(transactionId) {
        return this.makeRequest("GET", `/inApps/v1/transactions/${transactionId}`);
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses
     */
    async getSubscriptionStatuses(transactionId, query = {}) {
        const path = this.addQuery(`/inApps/v1/subscriptions/${transactionId}`, {
            ...query,
        });
        return this.makeRequest("GET", path);
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/look_up_order_id
     */
    async lookupOrder(orderId) {
        return this.makeRequest("GET", `/inApps/v1/lookup/${orderId}`);
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/extend_a_subscription_renewal_date
     */
    async extendSubscriptionRenewalDate(originalTransactionId, request) {
        return this.makeRequest("PUT", `/inApps/v1/subscriptions/extend/${originalTransactionId}`, request);
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/request_a_test_notification
     */
    async requestTestNotification() {
        return this.makeRequest("POST", "/inApps/v1/notifications/test");
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_test_notification_status
     */
    async getTestNotificationStatus(id) {
        return this.makeRequest("GET", `/inApps/v1/notifications/test/${id}`);
    }
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_notification_history
     */
    async getNotificationHistory(request, query = {}) {
        const path = this.addQuery("/inApps/v1/notifications/history", {
            ...query,
        });
        return this.makeRequest("POST", path, request);
    }
    /**
     * Performs a network request against the API and handles the result.
     */
    async makeRequest(method, path, body) {
        const token = await this.getToken();
        const url = this.baseUrl + path;
        const serializedBody = body ? JSON.stringify(body) : undefined;
        const result = await fetch(url, {
            method: method,
            body: serializedBody,
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
        });
        if (result.status === 200) {
            return result.json();
        }
        switch (result.status) {
            case 400:
            case 403:
            case 404:
            case 429:
            case 500: {
                const body = await result.json();
                throw new Errors_1.AppStoreError(body.errorCode, body.errorMessage);
            }
            case 401:
                this.token = undefined;
                throw new Error("The request is unauthorized; the JSON Web Token (JWT) is invalid.");
            default:
                throw new Error("An unknown error occurred");
        }
    }
    /**
     * Returns an existing authentication token (if its still valid) or generates a new one.
     */
    async getToken() {
        // Reuse previously created token if it hasn't expired.
        if (this.token && !this.tokenExpired)
            return this.token;
        // Tokens must expire after at most 1 hour.
        const now = new Date();
        const expiry = new Date(now.getTime() + AppStoreServerAPI.maxTokenAge * 1000);
        const expirySeconds = Math.floor(expiry.getTime() / 1000);
        const payload = {
            bid: this.bundleId,
            nonce: (0, uuid_1.v4)(),
        };
        const privateKey = await this.key;
        const jwt = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: "ES256", kid: this.keyId, typ: "JWT" })
            .setIssuer(this.issuerId)
            .setIssuedAt()
            .setExpirationTime(expirySeconds)
            .setAudience("appstoreconnect-v1")
            .sign(privateKey);
        this.token = jwt;
        this.tokenExpiry = expiry;
        return jwt;
    }
    /**
     * Returns whether the previously generated token can still be used.
     */
    get tokenExpired() {
        // We consider the token to be expired slightly before it actually is to allow for some networking latency.
        const headroom = 60; // seconds
        const now = new Date();
        const cutoff = new Date(now.getTime() - headroom * 1000);
        return !this.tokenExpiry || this.tokenExpiry < cutoff;
    }
    /**
     * Serializes a query object into a query string and appends it
     * the provided path.
     */
    addQuery(path, query) {
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(query)) {
            if (Array.isArray(value)) {
                for (const item of value) {
                    params.append(key, item.toString());
                }
            }
            else {
                params.set(key, value.toString());
            }
        }
        const queryString = params.toString();
        if (queryString === "") {
            return path;
        }
        else {
            return `${path}?${queryString}`;
        }
    }
}
exports.AppStoreServerAPI = AppStoreServerAPI;
// The maximum age that an authentication token is allowed to have, as decided by Apple.
AppStoreServerAPI.maxTokenAge = 3600; // seconds, = 1 hour
