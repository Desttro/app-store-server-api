export var Environment;
(function (Environment) {
    Environment["Production"] = "Production";
    Environment["Sandbox"] = "Sandbox";
})(Environment || (Environment = {}));
export var SortParameter;
(function (SortParameter) {
    SortParameter["Ascending"] = "ASCENDING";
    SortParameter["Descending"] = "DESCENDING";
})(SortParameter || (SortParameter = {}));
export var ProductTypeParameter;
(function (ProductTypeParameter) {
    ProductTypeParameter["AutoRenewable"] = "AUTO_RENEWABLE";
    ProductTypeParameter["NonRenewable"] = "NON_RENEWABLE";
    ProductTypeParameter["Consumable"] = "CONSUMABLE";
    ProductTypeParameter["NonConsumable"] = "NON_CONSUMABLE";
})(ProductTypeParameter || (ProductTypeParameter = {}));
// https://developer.apple.com/documentation/appstoreserverapi/inappownershiptype
export var OwnershipType;
(function (OwnershipType) {
    OwnershipType["Purchased"] = "PURCHASED";
    OwnershipType["FamilyShared"] = "FAMILY_SHARED";
})(OwnershipType || (OwnershipType = {}));
// https://developer.apple.com/documentation/appstoreserverapi/type
export var TransactionType;
(function (TransactionType) {
    TransactionType["AutoRenewableSubscription"] = "Auto-Renewable Subscription";
    TransactionType["NonConsumable"] = "Non-Consumable";
    TransactionType["Consumable"] = "Consumable";
    TransactionType["NonRenewingSubscription"] = "Non-Renewing Subscription";
})(TransactionType || (TransactionType = {}));
// https://developer.apple.com/documentation/appstoreservernotifications/transactionreason
export var TransactionReason;
(function (TransactionReason) {
    TransactionReason["Purchase"] = "PURCHASE";
    TransactionReason["Renewal"] = "RENEWAL";
})(TransactionReason || (TransactionReason = {}));
// https://developer.apple.com/documentation/appstoreserverapi/status
export var SubscriptionStatus;
(function (SubscriptionStatus) {
    SubscriptionStatus[SubscriptionStatus["Active"] = 1] = "Active";
    SubscriptionStatus[SubscriptionStatus["Expired"] = 2] = "Expired";
    SubscriptionStatus[SubscriptionStatus["InBillingRetry"] = 3] = "InBillingRetry";
    SubscriptionStatus[SubscriptionStatus["InBillingGracePeriod"] = 4] = "InBillingGracePeriod";
    SubscriptionStatus[SubscriptionStatus["Revoked"] = 5] = "Revoked";
})(SubscriptionStatus || (SubscriptionStatus = {}));
// https://developer.apple.com/documentation/appstoreserverapi/autorenewstatus
export var AutoRenewStatus;
(function (AutoRenewStatus) {
    AutoRenewStatus[AutoRenewStatus["Off"] = 0] = "Off";
    AutoRenewStatus[AutoRenewStatus["On"] = 1] = "On";
})(AutoRenewStatus || (AutoRenewStatus = {}));
// https://developer.apple.com/documentation/appstoreserverapi/expirationintent
export var ExpirationIntent;
(function (ExpirationIntent) {
    ExpirationIntent[ExpirationIntent["Canceled"] = 1] = "Canceled";
    ExpirationIntent[ExpirationIntent["BillingError"] = 2] = "BillingError";
    ExpirationIntent[ExpirationIntent["RejectedPriceIncrease"] = 3] = "RejectedPriceIncrease";
    ExpirationIntent[ExpirationIntent["ProductUnavailable"] = 4] = "ProductUnavailable";
})(ExpirationIntent || (ExpirationIntent = {}));
// https://developer.apple.com/documentation/appstoreserverapi/offertype
export var OfferType;
(function (OfferType) {
    OfferType[OfferType["Introductory"] = 1] = "Introductory";
    OfferType[OfferType["Promotional"] = 2] = "Promotional";
    OfferType[OfferType["SubscriptionOfferCode"] = 3] = "SubscriptionOfferCode";
})(OfferType || (OfferType = {}));
// https://developer.apple.com/documentation/appstoreserverapi/priceincreasestatus
export var PriceIncreaseStatus;
(function (PriceIncreaseStatus) {
    PriceIncreaseStatus[PriceIncreaseStatus["NoResponse"] = 0] = "NoResponse";
    PriceIncreaseStatus[PriceIncreaseStatus["Consented"] = 1] = "Consented";
})(PriceIncreaseStatus || (PriceIncreaseStatus = {}));
// https://developer.apple.com/documentation/appstoreserverapi/orderlookupstatus
export var OrderLookupStatus;
(function (OrderLookupStatus) {
    OrderLookupStatus[OrderLookupStatus["Valid"] = 0] = "Valid";
    OrderLookupStatus[OrderLookupStatus["Invalid"] = 1] = "Invalid";
})(OrderLookupStatus || (OrderLookupStatus = {}));
export function isDecodedNotificationDataPayload(decodedNotificationPayload) {
    return "data" in decodedNotificationPayload;
}
export function isDecodedNotificationSummaryPayload(decodedNotificationPayload) {
    return "summary" in decodedNotificationPayload;
}
// https://developer.apple.com/documentation/appstoreservernotifications/notificationtype
export var NotificationType;
(function (NotificationType) {
    NotificationType["ConsumptionRequest"] = "CONSUMPTION_REQUEST";
    NotificationType["DidChangeRenewalPref"] = "DID_CHANGE_RENEWAL_PREF";
    NotificationType["DidChangeRenewalStatus"] = "DID_CHANGE_RENEWAL_STATUS";
    NotificationType["DidFailToRenew"] = "DID_FAIL_TO_RENEW";
    NotificationType["DidRenew"] = "DID_RENEW";
    NotificationType["Expired"] = "EXPIRED";
    NotificationType["GracePeriodExpired"] = "GRACE_PERIOD_EXPIRED";
    NotificationType["OfferRedeemed"] = "OFFER_REDEEMED";
    NotificationType["PriceIncrease"] = "PRICE_INCREASE";
    NotificationType["Refund"] = "REFUND";
    NotificationType["RefundDeclined"] = "REFUND_DECLINED";
    NotificationType["RenewalExtended"] = "RENEWAL_EXTENDED";
    NotificationType["Revoke"] = "REVOKE";
    NotificationType["Subscribed"] = "SUBSCRIBED";
    NotificationType["RenewalExtension"] = "RENEWAL_EXTENSION";
    NotificationType["RefundReversed"] = "REFUND_REVERSED";
})(NotificationType || (NotificationType = {}));
// https://developer.apple.com/documentation/appstoreservernotifications/subtype
export var NotificationSubtype;
(function (NotificationSubtype) {
    NotificationSubtype["InitialBuy"] = "INITIAL_BUY";
    NotificationSubtype["Resubscribe"] = "RESUBSCRIBE";
    NotificationSubtype["Downgrade"] = "DOWNGRADE";
    NotificationSubtype["Upgrade"] = "UPGRADE";
    NotificationSubtype["AutoRenewEnabled"] = "AUTO_RENEW_ENABLED";
    NotificationSubtype["AutoRenewDisabled"] = "AUTO_RENEW_DISABLED";
    NotificationSubtype["Voluntary"] = "VOLUNTARY";
    NotificationSubtype["BillingRetry"] = "BILLING_RETRY";
    NotificationSubtype["PriceIncrease"] = "PRICE_INCREASE";
    NotificationSubtype["GracePeriod"] = "GRACE_PERIOD";
    NotificationSubtype["BillingRecovery"] = "BILLING_RECOVERY";
    NotificationSubtype["Pending"] = "PENDING";
    NotificationSubtype["Accepted"] = "ACCEPTED";
    NotificationSubtype["Summary"] = "SUMMARY";
    NotificationSubtype["Failure"] = "FAILURE";
})(NotificationSubtype || (NotificationSubtype = {}));
// https://developer.apple.com/documentation/appstoreserverapi/sendattemptresult
export var SendAttemptResult;
(function (SendAttemptResult) {
    SendAttemptResult["Success"] = "SUCCESS";
    SendAttemptResult["TimedOut"] = "TIMED_OUT";
    SendAttemptResult["TlsIssue"] = "TLS_ISSUE";
    SendAttemptResult["CircularRedirect"] = "CIRCULAR_REDIRECT";
    SendAttemptResult["NoResponse"] = "NO_RESPONSE";
    SendAttemptResult["SocketIssue"] = "SOCKET_ISSUE";
    SendAttemptResult["UnsupportedCharset"] = "UNSUPPORTED_CHARSET";
    SendAttemptResult["InvalidResponse"] = "INVALID_RESPONSE";
    SendAttemptResult["PrematureClose"] = "PREMATURE_CLOSE";
    SendAttemptResult["Other"] = "OTHER";
})(SendAttemptResult || (SendAttemptResult = {}));
// https://developer.apple.com/documentation/appstoreserverapi/extendrenewaldaterequest
export var ExtendReasonCode;
(function (ExtendReasonCode) {
    ExtendReasonCode[ExtendReasonCode["UNDECLARED"] = 0] = "UNDECLARED";
    ExtendReasonCode[ExtendReasonCode["CUSTOMER_SATISFACTION"] = 1] = "CUSTOMER_SATISFACTION";
    ExtendReasonCode[ExtendReasonCode["OTHER_REASON"] = 2] = "OTHER_REASON";
    ExtendReasonCode[ExtendReasonCode["SERVICE_ISSUE"] = 3] = "SERVICE_ISSUE";
})(ExtendReasonCode || (ExtendReasonCode = {}));
