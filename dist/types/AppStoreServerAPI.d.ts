import { CheckTestNotificationResponse, Environment, ExtendRenewalDateRequest, ExtendRenewalDateResponse, HistoryResponse, NotificationHistoryQuery, NotificationHistoryRequest, NotificationHistoryResponse, OrderLookupResponse, SendTestNotificationResponse, StatusResponse, SubscriptionStatusesQuery, TransactionHistoryQuery, TransactionInfoResponse } from "./Models";
export declare class AppStoreServerAPI {
    static readonly maxTokenAge: number;
    readonly environment: Environment;
    private readonly baseUrl;
    private readonly key;
    private readonly keyId;
    private readonly issuerId;
    private readonly bundleId;
    private token?;
    private tokenExpiry;
    /**
     * @param key the key downloaded from App Store Connect in PEM-encoded PKCS8 format.
     * @param keyId the id of the key, retrieved from App Store Connect
     * @param issuerId your issuer ID, retrieved from App Store Connect
     * @param bundleId bundle ID of your app
     */
    constructor(key: string, keyId: string, issuerId: string, bundleId: string, environment?: Environment);
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history
     */
    getTransactionHistory(transactionId: string, query?: TransactionHistoryQuery): Promise<HistoryResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_transaction_info
     */
    getTransactionInfo(transactionId: string): Promise<TransactionInfoResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses
     */
    getSubscriptionStatuses(transactionId: string, query?: SubscriptionStatusesQuery): Promise<StatusResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/look_up_order_id
     */
    lookupOrder(orderId: string): Promise<OrderLookupResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/extend_a_subscription_renewal_date
     */
    extendSubscriptionRenewalDate(originalTransactionId: string, request: ExtendRenewalDateRequest): Promise<ExtendRenewalDateResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/request_a_test_notification
     */
    requestTestNotification(): Promise<SendTestNotificationResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_test_notification_status
     */
    getTestNotificationStatus(id: string): Promise<CheckTestNotificationResponse>;
    /**
     * https://developer.apple.com/documentation/appstoreserverapi/get_notification_history
     */
    getNotificationHistory(request: NotificationHistoryRequest, query?: NotificationHistoryQuery): Promise<NotificationHistoryResponse>;
    /**
     * Performs a network request against the API and handles the result.
     */
    private makeRequest;
    /**
     * Returns an existing authentication token (if its still valid) or generates a new one.
     */
    private getToken;
    /**
     * Returns whether the previously generated token can still be used.
     */
    private get tokenExpired();
    /**
     * Serializes a query object into a query string and appends it
     * the provided path.
     */
    private addQuery;
}
