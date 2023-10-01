"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExtendReasonCode = exports.SendAttemptResult = exports.NotificationSubtype = exports.NotificationType = exports.isDecodedNotificationSummaryPayload = exports.isDecodedNotificationDataPayload = exports.OrderLookupStatus = exports.PriceIncreaseStatus = exports.OfferType = exports.ExpirationIntent = exports.AutoRenewStatus = exports.SubscriptionStatus = exports.TransactionReason = exports.TransactionType = exports.OwnershipType = exports.ProductTypeParameter = exports.SortParameter = exports.Environment = void 0;
var Environment;
(function (Environment) {
    Environment["Production"] = "Production";
    Environment["Sandbox"] = "Sandbox";
})(Environment || (exports.Environment = Environment = {}));
var SortParameter;
(function (SortParameter) {
    SortParameter["Ascending"] = "ASCENDING";
    SortParameter["Descending"] = "DESCENDING";
})(SortParameter || (exports.SortParameter = SortParameter = {}));
var ProductTypeParameter;
(function (ProductTypeParameter) {
    ProductTypeParameter["AutoRenewable"] = "AUTO_RENEWABLE";
    ProductTypeParameter["NonRenewable"] = "NON_RENEWABLE";
    ProductTypeParameter["Consumable"] = "CONSUMABLE";
    ProductTypeParameter["NonConsumable"] = "NON_CONSUMABLE";
})(ProductTypeParameter || (exports.ProductTypeParameter = ProductTypeParameter = {}));
// https://developer.apple.com/documentation/appstoreserverapi/inappownershiptype
var OwnershipType;
(function (OwnershipType) {
    OwnershipType["Purchased"] = "PURCHASED";
    OwnershipType["FamilyShared"] = "FAMILY_SHARED";
})(OwnershipType || (exports.OwnershipType = OwnershipType = {}));
// https://developer.apple.com/documentation/appstoreserverapi/type
var TransactionType;
(function (TransactionType) {
    TransactionType["AutoRenewableSubscription"] = "Auto-Renewable Subscription";
    TransactionType["NonConsumable"] = "Non-Consumable";
    TransactionType["Consumable"] = "Consumable";
    TransactionType["NonRenewingSubscription"] = "Non-Renewing Subscription";
})(TransactionType || (exports.TransactionType = TransactionType = {}));
// https://developer.apple.com/documentation/appstoreservernotifications/transactionreason
var TransactionReason;
(function (TransactionReason) {
    TransactionReason["Purchase"] = "PURCHASE";
    TransactionReason["Renewal"] = "RENEWAL";
})(TransactionReason || (exports.TransactionReason = TransactionReason = {}));
// https://developer.apple.com/documentation/appstoreserverapi/status
var SubscriptionStatus;
(function (SubscriptionStatus) {
    SubscriptionStatus[SubscriptionStatus["Active"] = 1] = "Active";
    SubscriptionStatus[SubscriptionStatus["Expired"] = 2] = "Expired";
    SubscriptionStatus[SubscriptionStatus["InBillingRetry"] = 3] = "InBillingRetry";
    SubscriptionStatus[SubscriptionStatus["InBillingGracePeriod"] = 4] = "InBillingGracePeriod";
    SubscriptionStatus[SubscriptionStatus["Revoked"] = 5] = "Revoked";
})(SubscriptionStatus || (exports.SubscriptionStatus = SubscriptionStatus = {}));
// https://developer.apple.com/documentation/appstoreserverapi/autorenewstatus
var AutoRenewStatus;
(function (AutoRenewStatus) {
    AutoRenewStatus[AutoRenewStatus["Off"] = 0] = "Off";
    AutoRenewStatus[AutoRenewStatus["On"] = 1] = "On";
})(AutoRenewStatus || (exports.AutoRenewStatus = AutoRenewStatus = {}));
// https://developer.apple.com/documentation/appstoreserverapi/expirationintent
var ExpirationIntent;
(function (ExpirationIntent) {
    ExpirationIntent[ExpirationIntent["Canceled"] = 1] = "Canceled";
    ExpirationIntent[ExpirationIntent["BillingError"] = 2] = "BillingError";
    ExpirationIntent[ExpirationIntent["RejectedPriceIncrease"] = 3] = "RejectedPriceIncrease";
    ExpirationIntent[ExpirationIntent["ProductUnavailable"] = 4] = "ProductUnavailable";
})(ExpirationIntent || (exports.ExpirationIntent = ExpirationIntent = {}));
// https://developer.apple.com/documentation/appstoreserverapi/offertype
var OfferType;
(function (OfferType) {
    OfferType[OfferType["Introductory"] = 1] = "Introductory";
    OfferType[OfferType["Promotional"] = 2] = "Promotional";
    OfferType[OfferType["SubscriptionOfferCode"] = 3] = "SubscriptionOfferCode";
})(OfferType || (exports.OfferType = OfferType = {}));
// https://developer.apple.com/documentation/appstoreserverapi/priceincreasestatus
var PriceIncreaseStatus;
(function (PriceIncreaseStatus) {
    PriceIncreaseStatus[PriceIncreaseStatus["NoResponse"] = 0] = "NoResponse";
    PriceIncreaseStatus[PriceIncreaseStatus["Consented"] = 1] = "Consented";
})(PriceIncreaseStatus || (exports.PriceIncreaseStatus = PriceIncreaseStatus = {}));
// https://developer.apple.com/documentation/appstoreserverapi/orderlookupstatus
var OrderLookupStatus;
(function (OrderLookupStatus) {
    OrderLookupStatus[OrderLookupStatus["Valid"] = 0] = "Valid";
    OrderLookupStatus[OrderLookupStatus["Invalid"] = 1] = "Invalid";
})(OrderLookupStatus || (exports.OrderLookupStatus = OrderLookupStatus = {}));
function isDecodedNotificationDataPayload(decodedNotificationPayload) {
    return "data" in decodedNotificationPayload;
}
exports.isDecodedNotificationDataPayload = isDecodedNotificationDataPayload;
function isDecodedNotificationSummaryPayload(decodedNotificationPayload) {
    return "summary" in decodedNotificationPayload;
}
exports.isDecodedNotificationSummaryPayload = isDecodedNotificationSummaryPayload;
// https://developer.apple.com/documentation/appstoreservernotifications/notificationtype
var NotificationType;
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
})(NotificationType || (exports.NotificationType = NotificationType = {}));
// https://developer.apple.com/documentation/appstoreservernotifications/subtype
var NotificationSubtype;
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
})(NotificationSubtype || (exports.NotificationSubtype = NotificationSubtype = {}));
// https://developer.apple.com/documentation/appstoreserverapi/sendattemptresult
var SendAttemptResult;
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
})(SendAttemptResult || (exports.SendAttemptResult = SendAttemptResult = {}));
// https://developer.apple.com/documentation/appstoreserverapi/extendrenewaldaterequest
var ExtendReasonCode;
(function (ExtendReasonCode) {
    ExtendReasonCode[ExtendReasonCode["UNDECLARED"] = 0] = "UNDECLARED";
    ExtendReasonCode[ExtendReasonCode["CUSTOMER_SATISFACTION"] = 1] = "CUSTOMER_SATISFACTION";
    ExtendReasonCode[ExtendReasonCode["OTHER_REASON"] = 2] = "OTHER_REASON";
    ExtendReasonCode[ExtendReasonCode["SERVICE_ISSUE"] = 3] = "SERVICE_ISSUE";
})(ExtendReasonCode || (exports.ExtendReasonCode = ExtendReasonCode = {}));
