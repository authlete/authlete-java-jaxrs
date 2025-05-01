/*
 * Copyright (C) 2019 Authlete, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 */
package com.authlete.jaxrs.spi;


import java.net.URI;
import javax.ws.rs.core.Response;
import com.authlete.common.dto.DeviceCompleteRequest.Result;
import com.authlete.common.dto.Property;


/**
 * Service Provider Interface to work with {@link
 * com.authlete.jaxrs.DeviceCompleteRequestHandler DeviceCompleteRequestHandler}.
 *
 * <p>
 * An implementation of this interface must be given to the constructor
 * of {@link com.authlete.jaxrs.DeviceCompleteRequestHandler DeviceCompleteRequestHandler}
 * class.
 * </p>
 *
 * @since 2.18
 *
 * @author Hideki Ikeda
 */
public interface DeviceCompleteRequestHandlerSpi
{
    /**
     * Get the result of end-user authentication and authorization.
     *
     * @return
     *         The result of end-user authentication and authorization.
     */
    Result getResult();


    /**
     * Get the subject (= unique identifier) of the end-user.
     * It must consist of only ASCII letters and its length
     * must not exceed 100.
     *
     * <p>
     * In a typical case, the subject is a primary key or another
     * unique ID of the record that represents the end-user in
     * your user database.
     * </p>
     *
     * @return
     *         The subject (= unique identifier) of the end-user.
     */
    String getUserSubject();


    /**
     * Get the time when the end-user was authenticated.
     *
     * <p>
     * This method is called only when {@link #getResult()}
     * has returned {@link com.authlete.common.dto.DeviceCompleteRequest.Result#AUTHORIZED
     * AUTHORIZED}.
     * </p>
     *
     * @return
     *         The time when the end-user authentication occurred.
     *         The number of seconds since Unix epoch (1970-01-01).
     *         Return 0 if the time is unknown.
     */
    long getUserAuthenticatedAt();


    /**
     * Get the authentication context class reference (ACR) that was
     * satisfied when the end-user was authenticated.
     *
     * <p>
     * If you don't know what ACR is, return {@code null}.
     * </p>
     *
     * <p>
     * This method is called only when {@link #getResult()}
     * has returned {@link com.authlete.common.dto.DeviceCompleteRequest.Result#AUTHORIZED
     * AUTHORIZED}.
     * </p>
     *
     * @return
     *         The authentication context class reference (ACR) that
     *         was satisfied when the end-user was authenticated.
     */
    String getAcr();


    /**
     * Get the value of a claim of the user.
     *
     * <p>
     * This method may be called multiple times. Note that
     * this method is called only when {@link #getResult()}
     * has returned {@link com.authlete.common.dto.DeviceCompleteRequest.Result#AUTHORIZED
     * AUTHORIZED}.
     * </p>
     *
     *
     * @param claimName
     *         A claim name such as {@code name} and {@code family_name}.
     *         Standard claim names are listed in "<a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims"
     *         >5.1. Standard Claims</a>" of <a href=
     *         "http://openid.net/specs/openid-connect-core-1_0.html">OpenID
     *         Connect Core 1.0</a>. Java constant values that represent the
     *         standard claims are listed in {@link com.authlete.common.types.StandardClaims
     *         StandardClaims} class. The value of {@code claimName} does NOT
     *         contain a language tag.
     *
     * @return
     *         The claim value. {@code null} if the claim value of the claim
     *         is not available.
     */
    Object getUserClaim(String claimName);


    /**
     * Get scopes to be associated with the access token. If this method returns
     * a non-null value, the set of scopes will be used instead of the scopes
     * specified in the original device authorization request.
     *
     * @return
     *         Scopes to replace the scopes specified in the original
     *         device authorization request with. When {@code null} is
     *         returned from this method, replacement is not performed.
     */
    String[] getScopes();


    /**
     * Get extra properties to associate with an access token.
     *
     * <p>
     * This method is expected to return an array of extra properties.
     * The following is an example that returns an array containing one
     * extra property.
     * </p>
     *
     * <pre style="border: 1px solid gray; padding: 0.5em; margin: 1em;">
     * <span style="color: gray;">&#x40;Override</span>
     * <span style="color: purple; font-weight: bold;">public</span> {@link Property}[] getProperties()
     * {
     *     <span style="color: purple; font-weight: bold;">return</span> <span style="color: purple; font-weight: bold;">new</span> {@link Property}[] {
     *         <span style="color: purple; font-weight: bold;">new</span> {@link Property#Property(String, String)
     *     Property}(<span style="color: darkred;">"example_parameter"</span>, <span style="color: darkred;">"example_value"</span>)
     *     };
     * }</pre>
     *
     * <p>
     * Extra properties returned from this method will appear as top-level entries
     * in a JSON response from an authorization server as shown in <a href=
     * "https://tools.ietf.org/html/rfc6749#section-5.1">5.1. Successful Response</a>
     * in RFC 6749.
     * </p>
     *
     * <p>
     * Note that <b>there is an upper limit on the total size of extra properties</b>.
     * On the server side, the properties will be (1) converted to a multidimensional
     * string array, (2) converted to JSON, (3) encrypted by AES/CBC/PKCS5Padding, (4)
     * encoded by base64url, and then stored into the database. The length of the
     * resultant string must not exceed 65,535 in bytes. This is the upper limit, but
     * we think it is big enough.
     * </p>
     *
     * @return
     *         Extra properties. If {@code null} is returned, any extra property will
     *         not be associated.
     */
    Property[] getProperties();


    /**
     * Get the description of the error. This corresponds to the
     * {@code error_description} property in the response to the client.
     *
     * @return
     *         The description of the error.
     */
    String getErrorDescription();


    /**
     * Get the URI of a document which describes the error in detail. This
     * corresponds to the {@code error_uri} property in the response to the
     * client.
     *
     * @return
     *         The URI of a document which describes the error in detail.
     */
    URI getErrorUri();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/complete} API
     * is {@link com.authlete.common.dto.DeviceCompleteResponse.Action#SUCCESS
     * SUCCESS}, which means the API call has been processed successfully. Typically,
     * the authorization server should return a successful response to the web
     * browser the end-user is using.
     *
     * @return
     *         A response to the end-user.
     */
    Response onSuccess();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/complete} API
     * is {@link com.authlete.common.dto.DeviceCompleteResponse.Action#INVALID_REQUEST
     * INVALID_REQUEST}, which means the API call is invalid and probably, the
     * authorization server implementation has some bugs.
     *
     * @return
     *         A response to the end-user.
     */
    Response onInvalidRequest();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/complete} API
     * is {@link com.authlete.common.dto.DeviceCompleteResponse.Action#USER_CODE_EXPIRED
     * USER_CODE_EXPIRED}, which means the user code has expired. Typically, the
     * authorization server implementation should tell the end-user that the user
     * code has expired and urge her to re-initiate a device flow.
     *
     * @return
     *         A response to the end-user.
     */
    Response onUserCodeExpired();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/complete} API
     * is {@link com.authlete.common.dto.DeviceCompleteResponse.Action#USER_CODE_NOT_EXIST
     * USER_CODE_NOT_EXIST}, which means the user code does not exist. Typically,
     * the authorization server implementation should tell the end-user that the
     * user code has been invalidated and urge her to re-initiate a device flow.
     *
     * @return
     *         A response to the end-user.
     */
    Response onUserCodeNotExist();


    /**
     * Return a response to the end-user when the value of {@code action} parameter
     * contained in the response from Authlete {@code /api/device/complete} API
     * is {@link com.authlete.common.dto.DeviceCompleteResponse.Action#SERVER_ERROR
     * SERVER_ERROR}, which means an error occurred on Authlete side. Typically,
     * the authorization server implementation should tell the end-user that something
     * wrong happened and urge her to re-initiate a device flow.
     *
     * @return
     *         A response to the end-user.
     */
    Response onServerError();
}
