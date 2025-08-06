package com.authlete.jaxrs.migration;

import java.util.function.Function;

/**
 * An enum class that controls which response is returned from the
 * {@link AuthleteApiHolder#withApi(ResponseReturnStrategy, Function)} method under different scenarios.
 *
 * @author kylegonzalez
 */
public enum ResponseReturnStrategy {

    /**
     * Always return the primary API call response.
     */
    PRIMARY,

    /**
     * Always return the secondary API's call response.
     * <br/>
     * <br/>
     * <b>This should not be preferred since the 2.3 environment is not required to start up this application.</b>
     */
    SECONDARY,

    /**
     * Returns the first non-error response, prioritising the primary api then if it is an error response, then
     * the secondary API's response will be returned.
     */
    FIRST_NON_ERROR_RESPONSE,

    /**
     * Returns the last non-error response, which prioritises the secondary API unless the secondary's response is an
     * error, then the primary's response is returned.
     */
    LAST_NON_ERROR_RESPONSE,

    /**
     * If both APIs return an error response then the primary's response will be returned to the caller.
     */
    BOTH_ERROR_THEN_PRIMARY,

    /**
     * If both APIs return an error response then the secondary's response will be returned to the caller.
     */
    BOTH_ERROR_THEN_SECONDARY,

    /**
     * If one API results in an error response and the other in a success response then return the error response.
     */
    ONE_ERROR_THAN_ERROR,

    /**
     * If one API results in an error response and the other in a success response then return the success response.
     */
    ONE_ERROR_THAN_SUCCESS
}
