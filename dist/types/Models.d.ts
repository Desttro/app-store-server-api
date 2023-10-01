export declare enum Environment {
    Production = "Production",
    Sandbox = "Sandbox"
}
/**
 * UNIX timestamp in milliseconds
 */
export type Timestamp = number;
/**
 * ISO 3166-1 Alpha-3 country code
 * https://developer.apple.com/documentation/appstoreservernotifications/storefrontcountrycode
 */
export type StorefrontCountryCode = string;
export declare enum SortParameter {
    Ascending = "ASCENDING",
    Descending = "DESCENDING"
}
export declare enum ProductTypeParameter {
    AutoRenewable = "AUTO_RENEWABLE",
    NonRenewable = "NON_RENEWABLE",
    Consumable = "CONSUMABLE",
    NonConsumable = "NON_CONSUMABLE"
}
/**
 * The query parameters that can be passed to the history endpoint
 * to filter results and change sort order.
 * https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history
 */
export interface TransactionHistoryQuery {
    revision?: string;
    sort?: SortParameter;
    startDate?: Timestamp;
    endDate?: Timestamp;
    productType?: ProductTypeParameter;
    productId?: string;
    subscriptionGroupIdentifier?: string;
    inAppOwnershipType?: OwnershipType;
    revoked?: boolean;
}
export interface HistoryResponse {
    appAppleId: string;
    bundleId: string;
    environment: Environment;
    hasMore: boolean;
    revision: string;
    signedTransactions: JWSTransaction[];
}
export interface TransactionInfoResponse {
    signedTransactionInfo: JWSTransaction;
}
export type JWSTransaction = string;
export interface JWSDecodedHeader {
    alg: string;
    kid: string;
    x5c: string[];
}
export interface JWSTransactionDecodedPayload {
    appAccountToken?: string;
    bundleId: string;
    environment: Environment;
    expiresDate?: Timestamp;
    inAppOwnershipType: OwnershipType;
    isUpgraded?: boolean;
    offerIdentifier?: string;
    offerType?: OfferType;
    originalPurchaseDate: Timestamp;
    originalTransactionId: string;
    productId: string;
    purchaseDate: Timestamp;
    quantity: number;
    revocationDate?: Timestamp;
    revocationReason?: number;
    signedDate: Timestamp;
    storefront: StorefrontCountryCode;
    storefrontId: string;
    subscriptionGroupIdentifier?: string;
    transactionId: string;
    transactionReason: TransactionReason;
    type: TransactionType;
    webOrderLineItemId: string;
}
export declare enum OwnershipType {
    Purchased = "PURCHASED",
    FamilyShared = "FAMILY_SHARED"
}
export declare enum TransactionType {
    AutoRenewableSubscription = "Auto-Renewable Subscription",
    NonConsumable = "Non-Consumable",
    Consumable = "Consumable",
    NonRenewingSubscription = "Non-Renewing Subscription"
}
export declare enum TransactionReason {
    Purchase = "PURCHASE",
    Renewal = "RENEWAL"
}
export interface SubscriptionStatusesQuery {
    status?: SubscriptionStatus[];
}
export interface StatusResponse {
    data: SubscriptionGroupIdentifierItem[];
    environment: Environment;
    appAppleId: string;
    bundleId: string;
}
export interface SubscriptionGroupIdentifierItem {
    subscriptionGroupIdentifier: string;
    lastTransactions: LastTransactionsItem[];
}
export interface LastTransactionsItem {
    originalTransactionId: string;
    status: SubscriptionStatus;
    signedRenewalInfo: JWSRenewalInfo;
    signedTransactionInfo: JWSTransaction;
}
export type JWSRenewalInfo = string;
export declare enum SubscriptionStatus {
    Active = 1,
    Expired = 2,
    InBillingRetry = 3,
    InBillingGracePeriod = 4,
    Revoked = 5
}
export interface JWSRenewalInfoDecodedPayload {
    autoRenewProductId: string;
    autoRenewStatus: AutoRenewStatus;
    environment: Environment;
    expirationIntent?: ExpirationIntent;
    gracePeriodExpiresDate?: Timestamp;
    isInBillingRetryPeriod?: boolean;
    offerIdentifier?: string;
    offerType?: OfferType;
    originalTransactionId: string;
    priceIncreaseStatus?: PriceIncreaseStatus;
    productId: string;
    recentSubscriptionStartDate: Timestamp;
    renewalDate: Timestamp;
    signedDate: Timestamp;
}
export declare enum AutoRenewStatus {
    Off = 0,
    On = 1
}
export declare enum ExpirationIntent {
    Canceled = 1,
    BillingError = 2,
    RejectedPriceIncrease = 3,
    ProductUnavailable = 4
}
export declare enum OfferType {
    Introductory = 1,
    Promotional = 2,
    SubscriptionOfferCode = 3
}
export declare enum PriceIncreaseStatus {
    NoResponse = 0,
    Consented = 1
}
export interface OrderLookupResponse {
    status: OrderLookupStatus;
    signedTransactions: JWSTransaction[];
}
export declare enum OrderLookupStatus {
    Valid = 0,
    Invalid = 1
}
interface DecodedNotificationBasePayload {
    notificationType: NotificationType;
    subtype?: NotificationSubtype;
    notificationUUID: string;
    version: string;
    signedDate: Timestamp;
}
export interface DecodedNotificationDataPayload extends DecodedNotificationBasePayload {
    data: NotificationData;
    summary?: never;
}
export interface DecodedNotificationSummaryPayload extends DecodedNotificationBasePayload {
    data?: never;
    summary: NotificationSummary;
}
export type DecodedNotificationPayload = DecodedNotificationDataPayload | DecodedNotificationSummaryPayload;
export declare function isDecodedNotificationDataPayload(decodedNotificationPayload: DecodedNotificationPayload): decodedNotificationPayload is DecodedNotificationDataPayload;
export declare function isDecodedNotificationSummaryPayload(decodedNotificationPayload: DecodedNotificationPayload): decodedNotificationPayload is DecodedNotificationSummaryPayload;
export interface NotificationData {
    appAppleId: string;
    bundleId: string;
    bundleVersion: number;
    environment: Environment;
    signedRenewalInfo: JWSRenewalInfo;
    signedTransactionInfo: JWSTransaction;
    status?: SubscriptionStatus;
}
export interface NotificationSummary {
    requestIdentifier: string;
    environment: Environment;
    appAppleId: string;
    bundleId: string;
    productId: string;
    storefrontCountryCodes?: StorefrontCountryCode[];
    failedCount: number;
    succeededCount: number;
}
export declare enum NotificationType {
    ConsumptionRequest = "CONSUMPTION_REQUEST",
    DidChangeRenewalPref = "DID_CHANGE_RENEWAL_PREF",
    DidChangeRenewalStatus = "DID_CHANGE_RENEWAL_STATUS",
    DidFailToRenew = "DID_FAIL_TO_RENEW",
    DidRenew = "DID_RENEW",
    Expired = "EXPIRED",
    GracePeriodExpired = "GRACE_PERIOD_EXPIRED",
    OfferRedeemed = "OFFER_REDEEMED",
    PriceIncrease = "PRICE_INCREASE",
    Refund = "REFUND",
    RefundDeclined = "REFUND_DECLINED",
    RenewalExtended = "RENEWAL_EXTENDED",
    Revoke = "REVOKE",
    Subscribed = "SUBSCRIBED",
    RenewalExtension = "RENEWAL_EXTENSION",
    RefundReversed = "REFUND_REVERSED"
}
export declare enum NotificationSubtype {
    InitialBuy = "INITIAL_BUY",
    Resubscribe = "RESUBSCRIBE",
    Downgrade = "DOWNGRADE",
    Upgrade = "UPGRADE",
    AutoRenewEnabled = "AUTO_RENEW_ENABLED",
    AutoRenewDisabled = "AUTO_RENEW_DISABLED",
    Voluntary = "VOLUNTARY",
    BillingRetry = "BILLING_RETRY",
    PriceIncrease = "PRICE_INCREASE",
    GracePeriod = "GRACE_PERIOD",
    BillingRecovery = "BILLING_RECOVERY",
    Pending = "PENDING",
    Accepted = "ACCEPTED",
    Summary = "SUMMARY",
    Failure = "FAILURE"
}
export interface SendTestNotificationResponse {
    testNotificationToken: string;
}
export interface CheckTestNotificationResponse {
    sendAttempts: SendAttempt[];
    signedPayload: string;
}
export interface SendAttempt {
    attemptDate: Timestamp;
    sendAttemptResult: SendAttemptResult;
}
export declare enum SendAttemptResult {
    Success = "SUCCESS",
    TimedOut = "TIMED_OUT",
    TlsIssue = "TLS_ISSUE",
    CircularRedirect = "CIRCULAR_REDIRECT",
    NoResponse = "NO_RESPONSE",
    SocketIssue = "SOCKET_ISSUE",
    UnsupportedCharset = "UNSUPPORTED_CHARSET",
    InvalidResponse = "INVALID_RESPONSE",
    PrematureClose = "PREMATURE_CLOSE",
    Other = "OTHER"
}
export interface NotificationHistoryQuery {
    paginationToken?: string;
}
export interface NotificationHistoryRequest {
    startDate: Timestamp;
    endDate: Timestamp;
    notificationType?: NotificationType;
    notificationSubtype?: NotificationSubtype;
    onlyFailures?: boolean;
    transactionId?: string;
}
export interface NotificationHistoryResponse {
    notificationHistory: NotificationHistoryResponseItem[];
    hasMore: boolean;
    paginationToken: string;
}
export interface NotificationHistoryResponseItem {
    sendAttempts: SendAttempt[];
    signedPayload: string;
}
export declare enum ExtendReasonCode {
    UNDECLARED = 0,
    CUSTOMER_SATISFACTION = 1,
    OTHER_REASON = 2,
    SERVICE_ISSUE = 3
}
export interface ExtendRenewalDateRequest {
    extendByDays: number;
    extendReasonCode: ExtendReasonCode;
    requestIdentifier: string;
}
export interface ExtendRenewalDateResponse {
    effectiveDate: Timestamp;
    originalTransactionId: string;
    success: boolean;
    webOrderLineItemId: string;
}
export {};