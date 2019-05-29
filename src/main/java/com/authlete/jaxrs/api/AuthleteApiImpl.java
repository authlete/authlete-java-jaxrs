/*
 * Copyright (C) 2014-2019 Authlete, Inc.
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
package com.authlete.jaxrs.api;


import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.ResponseProcessingException;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.api.Settings;
import com.authlete.common.conf.AuthleteConfiguration;
import com.authlete.common.dto.ApiResponse;
import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.AuthorizedClientListResponse;
import com.authlete.common.dto.BackchannelAuthenticationCompleteRequest;
import com.authlete.common.dto.BackchannelAuthenticationCompleteResponse;
import com.authlete.common.dto.BackchannelAuthenticationFailRequest;
import com.authlete.common.dto.BackchannelAuthenticationFailResponse;
import com.authlete.common.dto.BackchannelAuthenticationIssueRequest;
import com.authlete.common.dto.BackchannelAuthenticationIssueResponse;
import com.authlete.common.dto.BackchannelAuthenticationRequest;
import com.authlete.common.dto.BackchannelAuthenticationResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientAuthorizationDeleteRequest;
import com.authlete.common.dto.ClientAuthorizationGetListRequest;
import com.authlete.common.dto.ClientAuthorizationUpdateRequest;
import com.authlete.common.dto.ClientListResponse;
import com.authlete.common.dto.ClientRegistrationRequest;
import com.authlete.common.dto.ClientRegistrationResponse;
import com.authlete.common.dto.ClientSecretRefreshResponse;
import com.authlete.common.dto.ClientSecretUpdateRequest;
import com.authlete.common.dto.ClientSecretUpdateResponse;
import com.authlete.common.dto.GrantedScopesGetResponse;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.JoseVerifyRequest;
import com.authlete.common.dto.JoseVerifyResponse;
import com.authlete.common.dto.RevocationRequest;
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.Service;
import com.authlete.common.dto.ServiceListResponse;
import com.authlete.common.dto.StandardIntrospectionRequest;
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.dto.TokenCreateRequest;
import com.authlete.common.dto.TokenCreateResponse;
import com.authlete.common.dto.TokenFailRequest;
import com.authlete.common.dto.TokenFailResponse;
import com.authlete.common.dto.TokenIssueRequest;
import com.authlete.common.dto.TokenIssueResponse;
import com.authlete.common.dto.TokenListResponse;
import com.authlete.common.dto.TokenRequest;
import com.authlete.common.dto.TokenResponse;
import com.authlete.common.dto.TokenUpdateRequest;
import com.authlete.common.dto.TokenUpdateResponse;
import com.authlete.common.dto.UserInfoIssueRequest;
import com.authlete.common.dto.UserInfoIssueResponse;
import com.authlete.common.dto.UserInfoRequest;
import com.authlete.common.dto.UserInfoResponse;
import com.authlete.common.web.BasicCredentials;


/**
 * The implementation of {@link AuthleteApi} using JAX-RS 2.0 client API.
 *
 * @author Takahiko Kawasaki
 */
public class AuthleteApiImpl implements AuthleteApi
{
    // "application/json;charset=UTF-8"
    private static final MediaType JSON_UTF8_TYPE = APPLICATION_JSON_TYPE.withCharset("UTF-8");


    private interface AuthleteApiCall<TResponse>
    {
        TResponse call();
    }


    private static final String AUTH_AUTHORIZATION_API_PATH                   = "/api/auth/authorization";
    private static final String AUTH_AUTHORIZATION_FAIL_API_PATH              = "/api/auth/authorization/fail";
    private static final String AUTH_AUTHORIZATION_ISSUE_API_PATH             = "/api/auth/authorization/issue";
    private static final String AUTH_TOKEN_API_PATH                           = "/api/auth/token";
    private static final String AUTH_TOKEN_CREATE_API_PATH                    = "/api/auth/token/create";
    private static final String AUTH_TOKEN_FAIL_API_PATH                      = "/api/auth/token/fail";
    private static final String AUTH_TOKEN_GET_LIST_API_PATH                  = "/api/auth/token/get/list";
    private static final String AUTH_TOKEN_ISSUE_API_PATH                     = "/api/auth/token/issue";
    private static final String AUTH_TOKEN_UPDATE_API_PATH                    = "/api/auth/token/update";
    private static final String AUTH_REVOCATION_API_PATH                      = "/api/auth/revocation";
    private static final String AUTH_USERINFO_API_PATH                        = "/api/auth/userinfo";
    private static final String AUTH_USERINFO_ISSUE_API_PATH                  = "/api/auth/userinfo/issue";
    private static final String AUTH_INTROSPECTION_API_PATH                   = "/api/auth/introspection";
    private static final String AUTH_INTROSPECTION_STANDARD_API_PATH          = "/api/auth/introspection/standard";
    private static final String SERVICE_CONFIGURATION_API_PATH                = "/api/service/configuration";
    private static final String SERVICE_CREATE_API_PATH                       = "/api/service/create";
    private static final String SERVICE_DELETE_API_PATH                       = "/api/service/delete/%d";
    private static final String SERVICE_GET_API_PATH                          = "/api/service/get/%d";
    private static final String SERVICE_GET_LIST_API_PATH                     = "/api/service/get/list";
    private static final String SERVICE_JWKS_GET_API_PATH                     = "/api/service/jwks/get";
    private static final String SERVICE_UPDATE_API_PATH                       = "/api/service/update/%d";
    private static final String CLIENT_CREATE_API_PATH                        = "/api/client/create";
    private static final String CLIENT_REGISTRATION_API_PATH                  = "/api/client/registration";
    private static final String CLIENT_REGISTRATION_GET_API_PATH              = "/api/client/registration/get";
    private static final String CLIENT_REGISTRATION_UPDATE_API_PATH           = "/api/client/registration/update";
    private static final String CLIENT_REGISTRATION_DELETE_API_PATH           = "/api/client/registration/delete";
    private static final String CLIENT_DELETE_API_PATH                        = "/api/client/delete/%d";
    private static final String CLIENT_GET_API_PATH                           = "/api/client/get/%d";
    private static final String CLIENT_GET_LIST_API_PATH                      = "/api/client/get/list";
    private static final String CLIENT_SECRET_REFRESH_API_PATH                = "/api/client/secret/refresh/%s";
    private static final String CLIENT_SECRET_UPDATE_API_PATH                 = "/api/client/secret/update/%s";
    private static final String CLIENT_UPDATE_API_PATH                        = "/api/client/update/%d";
    private static final String REQUESTABLE_SCOPES_DELETE_API_PATH            = "/api/client/extension/requestable_scopes/delete/%d";
    private static final String REQUESTABLE_SCOPES_GET_API_PATH               = "/api/client/extension/requestable_scopes/get/%d";
    private static final String REQUESTABLE_SCOPES_UPDATE_API_PATH            = "/api/client/extension/requestable_scopes/update/%d";
    private static final String GRANTED_SCOPES_GET_API_PATH                   = "/api/client/granted_scopes/get/%d";
    private static final String GRANTED_SCOPES_DELETE_API_PATH                = "/api/client/granted_scopes/delete/%d";
    private static final String CLIENT_AUTHORIZATION_DELETE_API_PATH          = "/api/client/authorization/delete/%d";
    private static final String CLIENT_AUTHORIZATION_GET_LIST_API_PATH        = "/api/client/authorization/get/list";
    private static final String CLIENT_AUTHORIZATION_UPDATE_API_PATH          = "/api/client/authorization/update/%d";
    private static final String JOSE_VERIFY_API_PATH                          = "/api/jose/verify";
    private static final String BACKCHANNEL_AUTHENTICATION_API_PATH           = "/api/backchannel/authentication";
    private static final String BACKCHANNEL_AUTHENTICATION_COMPLETE_API_PATH  = "/api/backchannel/authentication/complete";
    private static final String BACKCHANNEL_AUTHENTICATION_FAIL_API_PATH      = "/api/backchannel/authentication/fail";
    private static final String BACKCHANNEL_AUTHENTICATION_ISSUE_API_PATH     = "/api/backchannel/authentication/issue";


    private final String mBaseUrl;
    private final String mServiceOwnerAuth;
    private final String mServiceAuth;
    private final Settings mSettings;
    private javax.ws.rs.client.Client mJaxRsClient;

    private Object mConnectionTimeoutLock = new Object();
    private int mCurrentConnectionTimeout;

    private Object mReadTimeoutLock = new Object();
    private int mCurrentReadTimeout;

    private ClientBuilder jaxRsClientBuilder;

    /**
     * The constructor with an instance of {@link AuthleteConfiguration}.
     *
     * <p>
     * The existence of a constructor of this type is a required by
     * {@link com.authlete.common.api.AuthleteApiFactory AuthleteApiFactory}.
     * </p>
     *
     * @param configuration
     *         An instance of {@link AuthleteConfiguration}.
     */
    public AuthleteApiImpl(AuthleteConfiguration configuration)
    {
        if (configuration == null)
        {
            throw new IllegalArgumentException("configuration is null.");
        }

        mBaseUrl          = configuration.getBaseUrl();
        mServiceOwnerAuth = createServiceOwnerCredentials(configuration);
        mServiceAuth      = createServiceCredentials(configuration);
        mSettings         = new Settings();
    }


    /**
     * Create an authorization header for the service owner.
     */
    private String createServiceOwnerCredentials(AuthleteConfiguration configuration)
    {
        if (configuration.getServiceOwnerAccessToken() != null)
        {
            return "Bearer " + configuration.getServiceOwnerAccessToken();
        }
        else
        {
            String key    = configuration.getServiceOwnerApiKey();
            String secret = configuration.getServiceOwnerApiSecret();

            return new BasicCredentials(key, secret).format();
        }
    }


    /**
     * Create an authorization header for the service.
     */
    private String createServiceCredentials(AuthleteConfiguration configuration)
    {
        if (configuration.getServiceAccessToken() != null)
        {
            return "Bearer " + configuration.getServiceAccessToken();
        }
        else
        {
            String key    = configuration.getServiceApiKey();
            String secret = configuration.getServiceApiSecret();

            return new BasicCredentials(key, secret).format();
        }
    }


    /**
     * Get an instance of JAX-RS client.
     */
    private javax.ws.rs.client.Client getJaxRsClient()
    {
        // If a JAX-RS client has not been created yet.
        if (mJaxRsClient == null)
        {
            // Create a JAX-RS client.
            javax.ws.rs.client.Client client = createJaxRsClient();

            synchronized (this)
            {
                if (mJaxRsClient == null)
                {
                    mJaxRsClient = client;
                }
            }
        }

        // Set a connection timeout.
        setConnectionTimeout(mJaxRsClient);

        // Set a read timeout.
        setReadTimeout(mJaxRsClient);

        return mJaxRsClient;
    }


    /**
     * Create an instance of JAX-RS client.
     */
    private javax.ws.rs.client.Client createJaxRsClient()
    {
        if (getJaxRsClientBuilder() != null) {
            // if we have a builder configured, use it
            return getJaxRsClientBuilder().build();
        } else {
            // otherwise just use the system discovered default
            return ClientBuilder.newClient();
        }
    }


    /**
     * Set a connection timeout.
     */
    private void setConnectionTimeout(javax.ws.rs.client.Client client)
    {
        // The timeout value.
        int timeout = mSettings.getConnectionTimeout();

        synchronized (mConnectionTimeoutLock)
        {
            if (mCurrentConnectionTimeout == timeout)
            {
                // The given value is the same as the current one.
                // Let's skip calling property() method.
                return;
            }

            // The given value is different from the current value.
            // Let's update the configuration.
            mCurrentConnectionTimeout = timeout;
        }

        //----------------------------------------------------------------------
        // Note that there was no standardized way to set the connection timeout
        // before JAX-RS API 2.1 (Java EE 8) (cf. ClientBuilder.connectTimeout).
        //----------------------------------------------------------------------

        // Convert int to Integer before calling property() method multiple times
        // in order to reduce the number of object creation by autoboxing.
        Integer value = Integer.valueOf(timeout);

        // For Jersey
        client.property("jersey.config.client.connectTimeout", value);

        // For Apache CXF
        client.property("http.connection.timeout", value);

        // For WebSphere (8.5.5.7+)
        client.property("com.ibm.ws.jaxrs.client.connection.timeout", value);
    }


    /**
     * Set a read timeout.
     */
    private void setReadTimeout(javax.ws.rs.client.Client client)
    {
        // The timeout value.
        int timeout = mSettings.getReadTimeout();

        synchronized (mReadTimeoutLock)
        {
            if (mCurrentReadTimeout == timeout)
            {
                // The given value is the same as the current one.
                // Let's skip calling property() method.
                return;
            }

            // The given value is different from the current value.
            // Let's update the configuration.
            mCurrentReadTimeout = timeout;
        }

        //----------------------------------------------------------------------
        // Note that there was no standardized way to set the read timeout
        // before JAX-RS API 2.1 (Java EE 8) (cf. ClientBuilder.readTimeout).
        //----------------------------------------------------------------------

        // Convert int to Integer before calling property() method multiple times
        // in order to reduce the number of object creation by autoboxing.
        Integer value = Integer.valueOf(timeout);

        // For Jersey
        client.property("jersey.config.client.readTimeout", value);

        // For Apache CXF
        client.property("http.receive.timeout", value);

        // For WebSphere (8.5.5.7+)
        client.property("com.ibm.ws.jaxrs.client.receive.timeout", value);
    }


    private WebTarget getTarget()
    {
        return getJaxRsClient().target(mBaseUrl);
    }


    /**
     * Execute an Authlete API call.
     */
    private <TResponse> TResponse executeApiCall(AuthleteApiCall<TResponse> apiCall) throws AuthleteApiException
    {
        try
        {
            // Call the Authlete API.
            return apiCall.call();
        }
        catch (WebApplicationException e)
        {
            // Throw an exception with HTTP response information.
            throw createApiException(e, e.getResponse());
        }
        catch (ResponseProcessingException e)
        {
            // Throw an exception with HTTP response information.
            throw createApiException(e, e.getResponse());
        }
        catch (Throwable t)
        {
            // Throw an exception without HTTP response information.
            throw createApiException(t, null);
        }
    }


    /**
     * Create an {@link AuthleteApiException} instance.
     */
    private AuthleteApiException createApiException(Throwable cause, Response response)
    {
        // Error message.
        String message = cause.getMessage();

        if (response == null)
        {
            // Create an exception without HTTP response information.
            return new AuthleteApiException(message, cause);
        }

        // Status code and status message.
        int statusCode = 0;
        String statusMessage = null;

        // Get the status information.
        StatusType type = response.getStatusInfo();
        if (type != null)
        {
            statusCode    = type.getStatusCode();
            statusMessage = type.getReasonPhrase();
        }

        // Response body.
        String responseBody = null;

        // If the response has response body.
        if (hasEntity(response))
        {
            // Get the response body.
            responseBody = extractResponseBody(response);
        }

        // Response headers.
        Map<String, List<String>> headers = response.getStringHeaders();

        // Create an exception with HTTP response information.
        return new AuthleteApiException(message, cause, statusCode, statusMessage, responseBody, headers);
    }


    private boolean hasEntity(Response response)
    {
        try
        {
            // True if there is an entity available in the response.
            return response.hasEntity();
        }
        catch (IllegalStateException e)
        {
            // IllegalStateException is thrown in case the response has been closed.
            // A typical error message is "Entity input stream has already been closed."
            // Anyway, an entity is not available.
            return false;
        }
    }


    private String extractResponseBody(Response response)
    {
        try
        {
            // Convert the entity body into a String.
            return response.readEntity(String.class);
        }
        catch (Exception e)
        {
            // Failed to convert the entity body into a String.
            e.printStackTrace();

            // Response body is not available.
            return null;
        }
    }


    private <TResponse> TResponse callGetApi(
            String auth, String path, Class<TResponse> responseClass, Map<String, Object[]> params)
    {
        WebTarget webTarget = getTarget().path(path);

        if (params != null)
        {
            for (Map.Entry<String, Object[]> param : params.entrySet())
            {
                webTarget = webTarget.queryParam(param.getKey(), param.getValue());
            }
        }

        return webTarget
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, auth)
                .get(responseClass);
    }


    private <TResponse> TResponse callServiceOwnerGetApi(
            String path, Class<TResponse> responseClass, Map<String, Object[]> params)
    {
        return callGetApi(mServiceOwnerAuth, path, responseClass, params);
    }


    private <TResponse> TResponse callServiceGetApi(
            String path, Class<TResponse> responseClass, Map<String, Object[]> params)
    {
        return callGetApi(mServiceAuth, path, responseClass, params);
    }


    private Void callDeleteApi(String auth, String path)
    {
        getTarget()
            .path(path)
            .request()
            .header(AUTHORIZATION, auth)
            .delete();

        return null;
    }


    private Void callServiceOwnerDeleteApi(String path)
    {
        return callDeleteApi(mServiceOwnerAuth, path);
    }


    private Void callServiceDeleteApi(String path)
    {
        return callDeleteApi(mServiceAuth, path);
    }


    private <TResponse> TResponse callPostApi(String auth, String path, Object request, Class<TResponse> responseClass)
    {
        return getTarget()
                .path(path)
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, auth)
                .post(Entity.entity(request, JSON_UTF8_TYPE), responseClass);
    }


    private <TResponse> TResponse callServiceOwnerPostApi(String path, Object request, Class<TResponse> responseClass)
    {
        return callPostApi(mServiceOwnerAuth, path, request, responseClass);
    }


    private <TResponse> TResponse callServicePostApi(String path, Object request, Class<TResponse> responseClass)
    {
        return callPostApi(mServiceAuth, path, request, responseClass);
    }


    private static abstract class ApiCaller<TResponse> implements AuthleteApiCall<TResponse>
    {
        protected final String mPath;
        protected final Object mRequest;
        protected final Class<TResponse> mResponseClass;
        protected final Map<String, Object[]> mParams = new LinkedHashMap<>();


        ApiCaller(Class<TResponse> responseClass, Object request, String path)
        {
            mPath          = path;
            mRequest       = request;
            mResponseClass = responseClass;
        }


        ApiCaller(Class<TResponse> responseClass, Object request, String format, Object... args)
        {
            this(responseClass, request, String.format(format, args));
        }


        public ApiCaller<TResponse> addParam(String name, Object... values)
        {
            mParams.put(name, values);

            return this;
        }
    }


    private class ServiceOwnerDeleteApiCaller extends ApiCaller<Void>
    {
        ServiceOwnerDeleteApiCaller(String path)
        {
            super(Void.class, null, path);
        }


        ServiceOwnerDeleteApiCaller(String format, Object... args)
        {
            super(Void.class, null, format, args);
        }


        @Override
        public Void call()
        {
            return callServiceOwnerDeleteApi(mPath);
        }
    }


    private class ServiceOwnerGetApiCaller<TResponse> extends ApiCaller<TResponse>
    {
        ServiceOwnerGetApiCaller(Class<TResponse> responseClass, String path)
        {
            super(responseClass, null, path);
        }


        ServiceOwnerGetApiCaller(Class<TResponse> responseClass, String format, Object... args)
        {
            super(responseClass, null, format, args);
        }


        @Override
        public TResponse call()
        {
            return callServiceOwnerGetApi(mPath, mResponseClass, mParams);
        }
    }


    private class ServiceOwnerPostApiCaller<TResponse> extends ApiCaller<TResponse>
    {
        ServiceOwnerPostApiCaller(Class<TResponse> responseClass, Object request, String path)
        {
            super(responseClass, request, path);
        }


        ServiceOwnerPostApiCaller(Class<TResponse> responseClass, Object request, String format, Object... args)
        {
            super(responseClass, request, format, args);
        }


        @Override
        public TResponse call()
        {
            return callServiceOwnerPostApi(mPath, mRequest, mResponseClass);
        }
    }


    private class ServiceDeleteApiCaller extends ApiCaller<Void>
    {
        ServiceDeleteApiCaller(String path)
        {
            super(Void.class, null, path);
        }


        ServiceDeleteApiCaller(String format, Object... args)
        {
            super(Void.class, null, format, args);
        }


        @Override
        public Void call()
        {
            return callServiceDeleteApi(mPath);
        }
    }


    private class ServiceGetApiCaller<TResponse> extends ApiCaller<TResponse>
    {
        ServiceGetApiCaller(Class<TResponse> responseClass, String path)
        {
            super(responseClass, null, path);
        }


        ServiceGetApiCaller(Class<TResponse> responseClass, String format, Object... args)
        {
            super(responseClass, null, format, args);
        }


        @Override
        public TResponse call()
        {
            return callServiceGetApi(mPath, mResponseClass, mParams);
        }
    }


    private class ServicePostApiCaller<TResponse> extends ApiCaller<TResponse>
    {
        ServicePostApiCaller(Class<TResponse> responseClass, Object request, String path)
        {
            super(responseClass, request, path);
        }


        ServicePostApiCaller(Class<TResponse> responseClass, Object request, String format, Object... args)
        {
            super(responseClass, request, format, args);
        }


        @Override
        public TResponse call()
        {
            return callServicePostApi(mPath, mRequest, mResponseClass);
        }
    }


    /**
     * Call {@code /api/auth/authorization} API.
     */
    @Override
    public AuthorizationResponse authorization(AuthorizationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizationResponse>(
                        AuthorizationResponse.class, request, AUTH_AUTHORIZATION_API_PATH));
    }


    /**
     * Call {@code /api/auth/authorization/fail} API.
     */
    @Override
    public AuthorizationFailResponse authorizationFail(AuthorizationFailRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizationFailResponse>(
                        AuthorizationFailResponse.class, request, AUTH_AUTHORIZATION_FAIL_API_PATH));
    }


    /**
     * Call {@code /api/auth/authorization/issue} API.
     */
    @Override
    public AuthorizationIssueResponse authorizationIssue(AuthorizationIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizationIssueResponse>(
                        AuthorizationIssueResponse.class, request, AUTH_AUTHORIZATION_ISSUE_API_PATH));
    }


    /**
     * Call {@code /api/auth/token} API.
     */
    @Override
    public TokenResponse token(TokenRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenResponse>(
                        TokenResponse.class, request, AUTH_TOKEN_API_PATH));
    }


    /**
     * Call {@code /api/auth/token/create} API.
     */
    @Override
    public TokenCreateResponse tokenCreate(TokenCreateRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenCreateResponse>(
                        TokenCreateResponse.class, request, AUTH_TOKEN_CREATE_API_PATH));
    }


    /**
     * Call {@code /api/auth/token/fail} API.
     */
    @Override
    public TokenFailResponse tokenFail(TokenFailRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenFailResponse>(
                        TokenFailResponse.class, request, AUTH_TOKEN_FAIL_API_PATH));
    }


    /**
     * Call {@code /api/auth/token/issue} API.
     */
    @Override
    public TokenIssueResponse tokenIssue(TokenIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenIssueResponse>(
                        TokenIssueResponse.class, request, AUTH_TOKEN_ISSUE_API_PATH));
    }


    /**
     * Call {@code /api/auth/token/update} API.
     */
    @Override
    public TokenUpdateResponse tokenUpdate(TokenUpdateRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenUpdateResponse>(
                        TokenUpdateResponse.class, request, AUTH_TOKEN_UPDATE_API_PATH));
    }


    @Override
    public TokenListResponse getTokenList() throws AuthleteApiException
    {
        return getTokenList(null, null, 0, 0, false);
    }


    @Override
    public TokenListResponse getTokenList(String clientIdentifier, String subject) throws AuthleteApiException
    {
        return getTokenList(clientIdentifier, subject, 0, 0, false);
    }


    @Override
    public TokenListResponse getTokenList(int start, int end) throws AuthleteApiException
    {
        return getTokenList(null, null, start, end, true);
    }


    @Override
    public TokenListResponse getTokenList(String clientIdentifier, String subject, int start, int end) throws AuthleteApiException
    {
        return getTokenList(clientIdentifier, subject, start, end, true);
    }


    private TokenListResponse getTokenList(
            final String clientIdentifier, final String subject,
            final int start, final int end, final boolean rangeGiven) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<TokenListResponse>() {
            @Override
            public TokenListResponse call()
            {
                return callGetTokenList(clientIdentifier, subject, start, end, rangeGiven);
            }
        });
    }


    private TokenListResponse callGetTokenList(
            String clientIdentifier, String subject, int start, int end, boolean rangeGiven)
    {
        WebTarget target = getTarget().path(AUTH_TOKEN_GET_LIST_API_PATH);

        if (clientIdentifier != null)
        {
            target = target.queryParam("clientIdentifier", clientIdentifier);
        }

        if (subject != null)
        {
            target = target.queryParam("subject", subject);
        }

        if (rangeGiven)
        {
            target = target.queryParam("start", start).queryParam("end", end);
        }

        return target
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, mServiceAuth)
                .get(TokenListResponse.class);
    }


    /**
     * Call {@code /api/auth/revocation} API.
     */
    @Override
    public RevocationResponse revocation(RevocationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<RevocationResponse>(
                        RevocationResponse.class, request, AUTH_REVOCATION_API_PATH));
    }


    /**
     * Call {@code /api/auth/userinfo} API.
     */
    @Override
    public UserInfoResponse userinfo(UserInfoRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<UserInfoResponse>(
                        UserInfoResponse.class, request, AUTH_USERINFO_API_PATH));
    }


    /**
     * Call {@code /api/auth/userinfo/issue} API.
     */
    @Override
    public UserInfoIssueResponse userinfoIssue(UserInfoIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<UserInfoIssueResponse>(
                        UserInfoIssueResponse.class, request, AUTH_USERINFO_ISSUE_API_PATH));
    }


    /**
     * Call {@code /api/auth/introspection} API.
     */
    @Override
    public IntrospectionResponse introspection(IntrospectionRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<IntrospectionResponse>(
                        IntrospectionResponse.class, request, AUTH_INTROSPECTION_API_PATH));
    }


    /**
     * Call {@code /api/auth/introspection/standard} API.
     */
    @Override
    public StandardIntrospectionResponse standardIntrospection(
            StandardIntrospectionRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<StandardIntrospectionResponse>(
                        StandardIntrospectionResponse.class, request, AUTH_INTROSPECTION_STANDARD_API_PATH));
    }


    /**
     * Call {@code /api/service/create} API.
     */
    @Override
    public Service createService(Service service) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerPostApiCaller<Service>(
                        Service.class, service, SERVICE_CREATE_API_PATH));
    }


    /**
     * Call {@code /api/service/create} API.
     */
    @Override
    @Deprecated
    public Service createServie(Service service) throws AuthleteApiException
    {
        return createService(service);
    }


    /**
     * Call <code>/api/service/delete/<i>{serviceApiKey}</i></code> API.
     */
    @Override
    public void deleteService(long apiKey) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceOwnerDeleteApiCaller(
                        SERVICE_DELETE_API_PATH, apiKey));
    }


    /**
     * Call <code>/api/service/get/<i>{serviceApiKey}</i></code> API.
     */
    @Override
    public Service getService(long apiKey) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerGetApiCaller<Service>(
                        Service.class, SERVICE_GET_API_PATH, apiKey));
    }


    /**
     * Call {@code /api/service/get/list} API.
     */
    @Override
    public ServiceListResponse getServiceList() throws AuthleteApiException
    {
        return getServiceList(0, 0, false);
    }


    @Override
    public ServiceListResponse getServiceList(int start, int end) throws AuthleteApiException
    {
        return getServiceList(start, end, true);
    }


    private ServiceListResponse getServiceList(
            final int start, final int end, final boolean rangeGiven) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<ServiceListResponse>() {
            @Override
            public ServiceListResponse call()
            {
                return callGetServiceList(start, end, rangeGiven);
            }
        });
    }


    /**
     * Call <code>/service/get/list</code>.
     */
    private ServiceListResponse callGetServiceList(int start, int end, boolean rangeGiven)
    {
        WebTarget target = getTarget().path(SERVICE_GET_LIST_API_PATH);

        if (rangeGiven)
        {
            target = target.queryParam("start", start).queryParam("end", end);
        }

        return target
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, mServiceOwnerAuth)
                .get(ServiceListResponse.class);
    }


    /**
     * Call <code>/api/service/update/<i>{serviceApiKey}</i></code> API.
     */
    @Override
    public Service updateService(final Service service) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerPostApiCaller<Service>(
                        Service.class, service, SERVICE_UPDATE_API_PATH, service.getApiKey()));
    }


    /**
     * Call {@code /api/service/jwks/get} API
     */
    @Override
    public String getServiceJwks() throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_JWKS_GET_API_PATH));
    }


    /**
     * Call {@code /api/service/jwks/get} API
     */
    @Override
    public String getServiceJwks(boolean pretty, boolean includePrivateKeys) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_JWKS_GET_API_PATH)
                .addParam("pretty", pretty)
                .addParam("includePrivateKeys", includePrivateKeys));
    }


    /**
     * Call {@code /api/service/configuration} API
     */
    @Override
    public String getServiceConfiguration() throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_CONFIGURATION_API_PATH));
    }


    /**
     * Call {@code /api/service/configuration} API
     */
    @Override
    public String getServiceConfiguration(boolean pretty) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_CONFIGURATION_API_PATH)
                .addParam("pretty", pretty));
    }


    /**
     * Call {@code /api/client/create} API.
     */
    @Override
    public Client createClient(Client client) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<Client>(
                        Client.class, client, CLIENT_CREATE_API_PATH));
    }


    /**
     * Call {@code /api/client/registration} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientRegister(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_API_PATH));
    }


    /**
     * Call {@code /api/client/registration/get} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientGet(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_GET_API_PATH));
    }


    /**
     * Call {@code /api/client/registration/update} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientUpdate(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_UPDATE_API_PATH));
    }


    /**
     * Call {@code /api/client/registration/delete} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientDelete(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_DELETE_API_PATH));
    }


    /**
     * Call <code>/api/client/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteClient(final long clientId) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceDeleteApiCaller(
                        CLIENT_DELETE_API_PATH, clientId));
    }


    /**
     * Call <code>/api/client/get/<i>{clientId}</i></code> API.
     */
    @Override
    public Client getClient(final long clientId) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<Client>(
                        Client.class, CLIENT_GET_API_PATH, clientId));
    }


    /**
     * Call {@code /api/client/get/list} API.
     */
    @Override
    public ClientListResponse getClientList() throws AuthleteApiException
    {
        return getClientList(null, 0, 0, false);
    }


    @Override
    public ClientListResponse getClientList(String developer) throws AuthleteApiException
    {
        return getClientList(developer, 0, 0, false);
    }


    @Override
    public ClientListResponse getClientList(int start, int end) throws AuthleteApiException
    {
        return getClientList(null, start, end, true);
    }


    @Override
    public ClientListResponse getClientList(String developer, int start, int end) throws AuthleteApiException
    {
        return getClientList(developer, start, end, true);
    }


    private ClientListResponse getClientList(
            final String developer, final int start, final int end, final boolean rangeGiven) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<ClientListResponse>() {
            @Override
            public ClientListResponse call()
            {
                return callGetClientList(developer, start, end, rangeGiven);
            }
        });
    }


    private ClientListResponse callGetClientList(String developer, int start, int end, boolean rangeGiven)
    {
        WebTarget target = getTarget().path(CLIENT_GET_LIST_API_PATH);

        if (developer != null)
        {
            target = target.queryParam("developer", developer);
        }

        if (rangeGiven)
        {
            target = target.queryParam("start", start).queryParam("end", end);
        }

        return target
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, mServiceAuth)
                .get(ClientListResponse.class);
    }


    /**
     * Call <code>/api/client/update/<i>{clientId}</i></code> API.
     */
    @Override
    public Client updateClient(Client client) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<Client>(
                        Client.class, client, CLIENT_UPDATE_API_PATH, client.getClientId()));
    }



    /**
     * Call <code>/api/client/extension/requestable_scopes/get/<i>{clientId}</i></code> API.
     */
    @Override
    public String[] getRequestableScopes(long clientId) throws AuthleteApiException
    {
        // Call the API.
        RequestableScopes response = executeApiCall(
                new ServiceGetApiCaller<RequestableScopes>(
                        RequestableScopes.class, REQUESTABLE_SCOPES_GET_API_PATH, clientId));

        if (response != null)
        {
            // Extract 'requestableScopes' from the response.
            return response.getRequestableScopes();
        }
        else
        {
            return null;
        }
    }


    @Override
    public String[] setRequestableScopes(long clientId, String[] scopes) throws AuthleteApiException
    {
        // Prepare a request body.
        RequestableScopes request = new RequestableScopes().setRequestableScopes(scopes);

        // Call the API.
        RequestableScopes response = executeApiCall(
                new ServicePostApiCaller<RequestableScopes>(
                        RequestableScopes.class, request, REQUESTABLE_SCOPES_UPDATE_API_PATH, clientId));

        if (response != null)
        {
            // Extract 'requestableScopes' from the response.
            return response.getRequestableScopes();
        }
        else
        {
            return null;
        }
    }


    /**
     * Call <code>/api/client/extension/requestable_scopes/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteRequestableScopes(long clientId) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceDeleteApiCaller(
                        REQUESTABLE_SCOPES_DELETE_API_PATH, clientId));
    }


    @Override
    public GrantedScopesGetResponse getGrantedScopes(long clientId, String subject)
    {
        // Prepare a request body.
        GrantedScopesRequest request = new GrantedScopesRequest(subject);

        // Call the API.
        return executeApiCall(
                new ServicePostApiCaller<GrantedScopesGetResponse>(
                        GrantedScopesGetResponse.class, request, GRANTED_SCOPES_GET_API_PATH, clientId));
    }


    @Override
    public void deleteGrantedScopes(long clientId, String subject)
    {
        // Prepare a request body.
        GrantedScopesRequest request = new GrantedScopesRequest(subject);

        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request, GRANTED_SCOPES_DELETE_API_PATH, clientId));
    }


    private static final class GrantedScopesRequest
    {
        private String subject;


        public GrantedScopesRequest(String subject)
        {
            this.subject = subject;
        }


        @SuppressWarnings("unused")
        public String getSubject()
        {
            return subject;
        }


        @SuppressWarnings("unused")
        public void setSubject(String subject)
        {
            this.subject = subject;
        }
    }


    @Override
    public void deleteClientAuthorization(long clientId, String subject) throws AuthleteApiException
    {
        // Prepare a request body.
        ClientAuthorizationDeleteRequest request = new ClientAuthorizationDeleteRequest(subject);

        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_AUTHORIZATION_DELETE_API_PATH, clientId));
    }


    @Override
    public AuthorizedClientListResponse getClientAuthorizationList(ClientAuthorizationGetListRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizedClientListResponse>(
                        AuthorizedClientListResponse.class, request, CLIENT_AUTHORIZATION_GET_LIST_API_PATH));
    }


    @Override
    public void updateClientAuthorization(long clientId, ClientAuthorizationUpdateRequest request) throws AuthleteApiException
    {
        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_AUTHORIZATION_UPDATE_API_PATH, clientId));
    }


    @Override
    public ClientSecretRefreshResponse refreshClientSecret(long clientId) throws AuthleteApiException
    {
        return refreshClientSecret(String.valueOf(clientId));
    }


    @Override
    public ClientSecretRefreshResponse refreshClientSecret(String clientIdentifier) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<ClientSecretRefreshResponse>(
                        ClientSecretRefreshResponse.class,
                        CLIENT_SECRET_REFRESH_API_PATH, clientIdentifier));
    }


    @Override
    public ClientSecretUpdateResponse updateClientSecret(long clientId, String clientSecret) throws AuthleteApiException
    {
        return updateClientSecret(String.valueOf(clientId), clientSecret);
    }


    @Override
    public ClientSecretUpdateResponse updateClientSecret(String clientIdentifier, String clientSecret) throws AuthleteApiException
    {
        // Prepare a request body. setClientSecret(String) method
        // throws IllegalArgumentException if the given client secret
        // does not comply with the format.
        ClientSecretUpdateRequest request
            = new ClientSecretUpdateRequest().setClientSecret(clientSecret);

        return executeApiCall(
                new ServicePostApiCaller<ClientSecretUpdateResponse>(
                        ClientSecretUpdateResponse.class, request,
                        CLIENT_SECRET_UPDATE_API_PATH, clientIdentifier));
    }


    @Override
    public Settings getSettings()
    {
        return mSettings;
    }


    /**
     * Call {@code /api/jose/verify} API.
     */
    @Override
    public JoseVerifyResponse verifyJose(JoseVerifyRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<JoseVerifyResponse>(
                        JoseVerifyResponse.class, request, JOSE_VERIFY_API_PATH));
    }


    public ClientBuilder getJaxRsClientBuilder()
    {
        return jaxRsClientBuilder;
    }


    public void setJaxRsClientBuilder(ClientBuilder jaxRsClientBuilder)
    {
        this.jaxRsClientBuilder = jaxRsClientBuilder;
    }


    /**
     * Call {@code /api/backchannel/authentication} API.
     */
    @Override
    public BackchannelAuthenticationResponse backchannelAuthentication(BackchannelAuthenticationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationResponse>(
                        BackchannelAuthenticationResponse.class, request, BACKCHANNEL_AUTHENTICATION_API_PATH));
    }


    /**
     * Call {@code /api/backchannel/authentication/issue} API.
     */
    @Override
    public BackchannelAuthenticationIssueResponse backchannelAuthenticationIssue(BackchannelAuthenticationIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationIssueResponse>(
                        BackchannelAuthenticationIssueResponse.class, request, BACKCHANNEL_AUTHENTICATION_ISSUE_API_PATH));
    }


    /**
     * Call {@code /api/backchannel/authentication/fail} API.
     */
    @Override
    public BackchannelAuthenticationFailResponse backchannelAuthenticationFail(BackchannelAuthenticationFailRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationFailResponse>(
                        BackchannelAuthenticationFailResponse.class, request, BACKCHANNEL_AUTHENTICATION_FAIL_API_PATH));
    }


    /**
     * Call {@code /api/backchannel/authentication/complete} API.
     */
    @Override
    public BackchannelAuthenticationCompleteResponse backchannelAuthenticationComplete(BackchannelAuthenticationCompleteRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationCompleteResponse>(
                        BackchannelAuthenticationCompleteResponse.class, request, BACKCHANNEL_AUTHENTICATION_COMPLETE_API_PATH));
    }
}
