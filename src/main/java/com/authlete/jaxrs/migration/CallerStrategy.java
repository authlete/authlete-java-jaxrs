package com.authlete.jaxrs.migration;

/**
 * An enum class that controls which of the two authlete authentication servers to call.
 *
 * @author kylegonzalez
 */
public enum CallerStrategy {

    /**
     * Calls both configured authlete servers no matter what the response is from each. This is usually for scenarios
     * like token revocation where we want to ensure the token is revoked in both authlete api servers.
     */
    CALL_BOTH,

    /**
     * Calls only the primary Api (authlete 3 endpoint) and returns its response. This is generally used on endpoints
     * that are for authlete 3 features only.
     */
    ONLY_PRIMARY,

    /**
     * Calls the primary configured authlete server first and can return early if it is successful, otherwise
     * will fall back and request from the secondary server. This is the default used for almost all endpoint calls.
     */
    UNTIL_SUCCESS
}
