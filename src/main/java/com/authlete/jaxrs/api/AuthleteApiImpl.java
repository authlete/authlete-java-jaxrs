/*
 * Copyright (C) 2014-2024 Authlete, Inc.
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
import java.util.Map;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.api.Options;
import com.authlete.common.conf.AuthleteApiVersion;
import com.authlete.common.conf.AuthleteConfiguration;
import com.authlete.common.dto.*;
import com.authlete.common.types.TokenStatus;
import com.authlete.common.web.BasicCredentials;


/**
 * The implementation of {@link AuthleteApi} using JAX-RS 2.0 client API.
 *
 * @author Takahiko Kawasaki
 *
 *         For Authlete 2.x
 */
public class AuthleteApiImpl extends AuthleteApiJaxrsImpl
{
    private static final String AUTH_AUTHORIZATION_API_PATH                   = "/api/auth/authorization";
    private static final String AUTH_AUTHORIZATION_FAIL_API_PATH              = "/api/auth/authorization/fail";
    private static final String AUTH_AUTHORIZATION_ISSUE_API_PATH             = "/api/auth/authorization/issue";
    private static final String AUTH_AUTHORIZATION_TICKET_INFO_API_PATH       = "/api/auth/authorization/ticket/info";
    private static final String AUTH_AUTHORIZATION_TICKET_UPDATE_API_PATH     = "/api/auth/authorization/ticket/update";
    private static final String AUTH_TOKEN_API_PATH                           = "/api/auth/token";
    private static final String AUTH_TOKEN_CREATE_API_PATH                    = "/api/auth/token/create";
    private static final String AUTH_TOKEN_DELETE_API_PATH                    = "/api/auth/token/delete/%s";
    private static final String AUTH_TOKEN_FAIL_API_PATH                      = "/api/auth/token/fail";
    private static final String AUTH_TOKEN_GET_LIST_API_PATH                  = "/api/auth/token/get/list";
    private static final String AUTH_TOKEN_ISSUE_API_PATH                     = "/api/auth/token/issue";
    private static final String AUTH_TOKEN_REVOKE_API_PATH                    = "/api/auth/token/revoke";
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
    private static final String CLIENT_DELETE_API_PATH                        = "/api/client/delete/%s";
    private static final String CLIENT_GET_API_PATH                           = "/api/client/get/%s";
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
    private static final String DEVICE_AUTHORIZATION_API_PATH                 = "/api/device/authorization";
    private static final String DEVICE_COMPLETE_API_PATH                      = "/api/device/complete";
    private static final String DEVICE_VERIFICATION_API_PATH                  = "/api/device/verification";
    private static final String PUSHED_AUTH_REQ_API_PATH                      = "/api/pushed_auth_req";
    private static final String HSK_CREATE_API_PATH                           = "/api/hsk/create";
    private static final String HSK_DELETE_API_PATH                           = "/api/hsk/delete/%s";
    private static final String HSK_GET_API_PATH                              = "/api/hsk/get/%s";
    private static final String HSK_GET_LIST_API_PATH                         = "/api/hsk/get/list";
    private static final String ECHO_API_PATH                                 = "/api/misc/echo";
    private static final String GM_API_PATH                                   = "/api/gm";
    private static final String CLIENT_LOCK_FLAG_UPDATE_API_PATH              = "/api/client/lock_flag/update/%s";
    private static final String FEDERATION_CONFIGURATION_API_PATH             = "/api/federation/configuration";
    private static final String FEDERATION_REGISTRATION_API_PATH              = "/api/federation/registration";
    private static final String VCI_JWKS_API_PATH                             = "/api/vci/jwks";
    private static final String VCI_JWT_ISSUER_API_PATH                       = "/api/vci/jwtissuer";
    private static final String VCI_METADATA_API_PATH                         = "/api/vci/metadata";
    private static final String VCI_OFFER_CREATE_API_PATH                     = "/api/vci/offer/create";
    private static final String VCI_OFFER_INFO_API_PATH                       = "/api/vci/offer/info";
    private static final String VCI_SINGLE_PARSE_API_PATH                     = "/api/vci/single/parse";
    private static final String VCI_SINGLE_ISSUE_API_PATH                     = "/api/vci/single/issue";
    private static final String VCI_BATCH_PARSE_API_PATH                      = "/api/vci/batch/parse";
    private static final String VCI_BATCH_ISSUE_API_PATH                      = "/api/vci/batch/issue";
    private static final String VCI_DEFERRED_PARSE_API_PATH                   = "/api/vci/deferred/parse";
    private static final String VCI_DEFERRED_ISSUE_API_PATH                   = "/api/vci/deferred/issue";
    private static final String ID_TOKEN_REISSUE_API_PATH                     = "/api/idtoken/reissue";


    private final String mServiceOwnerAuth;
    private final String mServiceAuth;

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
        super(configuration);

        // Authlete API version specified by the configuration.
        AuthleteApiVersion version =
                AuthleteApiVersion.parse(configuration.getApiVersion());

        if (version != null && version != AuthleteApiVersion.V2)
        {
            throw new IllegalArgumentException("Configuration must be set to V2 for this implementation.");
        }

        mServiceOwnerAuth = createServiceOwnerCredentials(configuration);
        mServiceAuth      = createServiceCredentials(configuration);
    }


    /**
     * Create an authorization header for the service owner.
     */
    private String createServiceOwnerCredentials(AuthleteConfiguration configuration)
    {
        if (configuration.getServiceOwnerAccessToken() != null)
        {
            if (isDpopEnabled())
            {
                return "DPoP " + configuration.getServiceOwnerAccessToken();
            }
            else
            {
                return "Bearer " + configuration.getServiceOwnerAccessToken();
            }
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
            if (isDpopEnabled())
            {
                return "DPoP " + configuration.getServiceAccessToken();
            }
            else
            {
                return "Bearer " + configuration.getServiceAccessToken();
            }
        }
        else
        {
            String key    = configuration.getServiceApiKey();
            String secret = configuration.getServiceApiSecret();

            return new BasicCredentials(key, secret).format();
        }
    }


    private <TResponse> TResponse callServiceOwnerGetApi(
            String path, Class<TResponse> responseClass, Map<String, Object[]> params, Options options)
    {
        return callGetApi(mServiceOwnerAuth, path, responseClass, params, options);
    }


    private <TResponse> TResponse callServiceGetApi(
            String path, Class<TResponse> responseClass, Map<String, Object[]> params, Options options)
    {
        return callGetApi(mServiceAuth, path, responseClass, params, options);
    }


    private Void callServiceOwnerDeleteApi(String path, Options options)
    {
        return callDeleteApi(mServiceOwnerAuth, path, options);
    }


    private Void callServiceDeleteApi(String path, Options options)
    {
        return callDeleteApi(mServiceAuth, path, options);
    }


    private <TResponse> TResponse callServiceOwnerPostApi(String path, Object request, Class<TResponse> responseClass, Options options)
    {
        return callPostApi(mServiceOwnerAuth, path, request, responseClass, options);
    }


    private <TResponse> TResponse callServicePostApi(String path, Object request, Class<TResponse> responseClass, Options options)
    {
        return callPostApi(mServiceAuth, path, request, responseClass, options);
    }


    private static abstract class ApiCaller<TResponse> implements AuthleteApiCall<TResponse>
    {
        protected final String mPath;
        protected final Object mRequest;
        protected final Class<TResponse> mResponseClass;
        protected final Map<String, Object[]> mParams = new LinkedHashMap<>();
        protected Options mOptions;


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


        public ApiCaller<TResponse> setOptions(Options options)
        {
            mOptions = options;

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
            return callServiceOwnerDeleteApi(mPath, mOptions);
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
            return callServiceOwnerGetApi(mPath, mResponseClass, mParams, mOptions);
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
            return callServiceOwnerPostApi(mPath, mRequest, mResponseClass, mOptions);
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
            return callServiceDeleteApi(mPath, mOptions);
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
            return callServiceGetApi(mPath, mResponseClass, mParams, mOptions);
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
            return callServicePostApi(mPath, mRequest, mResponseClass, mOptions);
        }
    }


    /**
     * Call {@code /api/auth/authorization} API.
     */
    @Override
    public AuthorizationResponse authorization(AuthorizationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizationResponse>(
                        AuthorizationResponse.class, request, AUTH_AUTHORIZATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/authorization/fail} API.
     */
    @Override
    public AuthorizationFailResponse authorizationFail(AuthorizationFailRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizationFailResponse>(
                        AuthorizationFailResponse.class, request, AUTH_AUTHORIZATION_FAIL_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/authorization/issue} API.
     */
    @Override
    public AuthorizationIssueResponse authorizationIssue(AuthorizationIssueRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizationIssueResponse>(
                        AuthorizationIssueResponse.class, request, AUTH_AUTHORIZATION_ISSUE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/token} API.
     */
    @Override
    public TokenResponse token(TokenRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenResponse>(
                        TokenResponse.class, request, AUTH_TOKEN_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/token/create} API.
     */
    @Override
    public TokenCreateResponse tokenCreate(TokenCreateRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenCreateResponse>(
                        TokenCreateResponse.class, request, AUTH_TOKEN_CREATE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call <code>/api/auth/token/delete/<i>{token}</i></code> API.
     */
    @Override
    public void tokenDelete(String token, Options options) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceDeleteApiCaller(
                        AUTH_TOKEN_DELETE_API_PATH, token)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/token/fail} API.
     */
    @Override
    public TokenFailResponse tokenFail(TokenFailRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenFailResponse>(
                        TokenFailResponse.class, request, AUTH_TOKEN_FAIL_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/token/issue} API.
     */
    @Override
    public TokenIssueResponse tokenIssue(TokenIssueRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenIssueResponse>(
                        TokenIssueResponse.class, request, AUTH_TOKEN_ISSUE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/token/revoke} API.
     */
    @Override
    public TokenRevokeResponse tokenRevoke(TokenRevokeRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenRevokeResponse>(
                        TokenRevokeResponse.class, request, AUTH_TOKEN_REVOKE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/token/update} API.
     */
    @Override
    public TokenUpdateResponse tokenUpdate(TokenUpdateRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<TokenUpdateResponse>(
                        TokenUpdateResponse.class, request, AUTH_TOKEN_UPDATE_API_PATH)
                .setOptions(options));
    }


    @Override
    public TokenListResponse getTokenList(Options options) throws AuthleteApiException
    {
        return getTokenList(null, null, 0, 0, false, TokenStatus.ALL, options);
    }


    @Override
    public TokenListResponse getTokenList(TokenStatus tokenStatus, Options options) throws AuthleteApiException
    {
        return getTokenList(null, null, 0, 0, false, tokenStatus, options);
    }


    @Override
    public TokenListResponse getTokenList(String clientIdentifier, String subject, Options options) throws AuthleteApiException
    {
        return getTokenList(clientIdentifier, subject, 0, 0, false, TokenStatus.ALL, options);
    }


    @Override
    public TokenListResponse getTokenList(String clientIdentifier, String subject, TokenStatus tokenStatus, Options options) throws AuthleteApiException
    {
        return getTokenList(clientIdentifier, subject, 0, 0, false, tokenStatus, options);
    }


    @Override
    public TokenListResponse getTokenList(int start, int end, Options options) throws AuthleteApiException
    {
        return getTokenList(null, null, start, end, true, TokenStatus.ALL, options);
    }


    @Override
    public TokenListResponse getTokenList(int start, int end, TokenStatus tokenStatus, Options options) throws AuthleteApiException
    {
        return getTokenList(null, null, start, end, true, tokenStatus, options);
    }


    @Override
    public TokenListResponse getTokenList(String clientIdentifier, String subject, int start, int end, Options options) throws AuthleteApiException
    {
        return getTokenList(clientIdentifier, subject, start, end, true, TokenStatus.ALL, options);
    }


    @Override
    public TokenListResponse getTokenList(String clientIdentifier, String subject, int start, int end, TokenStatus tokenStatus, Options options) throws AuthleteApiException
    {
        return getTokenList(clientIdentifier, subject, start, end, true, tokenStatus, options);
    }


    private TokenListResponse getTokenList(
            final String clientIdentifier, final String subject,
            final int start, final int end, final boolean rangeGiven, TokenStatus tokenStatus, Options options) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<TokenListResponse>()
        {
            @Override
            public TokenListResponse call()
            {
                return callGetTokenList(clientIdentifier, subject, start, end, rangeGiven, tokenStatus, options);
            }
        });
    }


    private TokenListResponse callGetTokenList(
            String clientIdentifier, String subject, int start, int end, boolean rangeGiven, TokenStatus tokenStatus, Options options)
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

        target = target.queryParam("tokenStatus", tokenStatus.toString());

        Builder builder = wrapWithDpop(target
                .request(APPLICATION_JSON_TYPE), AUTH_TOKEN_GET_LIST_API_PATH, "GET")
                .header(AUTHORIZATION, mServiceAuth);

        setCustomRequestHeaders(builder, options);

        return builder.get(TokenListResponse.class);
    }


    /**
     * Call {@code /api/auth/revocation} API.
     */
    @Override
    public RevocationResponse revocation(RevocationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<RevocationResponse>(
                        RevocationResponse.class, request, AUTH_REVOCATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/userinfo} API.
     */
    @Override
    public UserInfoResponse userinfo(UserInfoRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<UserInfoResponse>(
                        UserInfoResponse.class, request, AUTH_USERINFO_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/userinfo/issue} API.
     */
    @Override
    public UserInfoIssueResponse userinfoIssue(UserInfoIssueRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<UserInfoIssueResponse>(
                        UserInfoIssueResponse.class, request, AUTH_USERINFO_ISSUE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/introspection} API.
     */
    @Override
    public IntrospectionResponse introspection(IntrospectionRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<IntrospectionResponse>(
                        IntrospectionResponse.class, request, AUTH_INTROSPECTION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/auth/introspection/standard} API.
     */
    @Override
    public StandardIntrospectionResponse standardIntrospection(
            StandardIntrospectionRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<StandardIntrospectionResponse>(
                        StandardIntrospectionResponse.class, request, AUTH_INTROSPECTION_STANDARD_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/create} API.
     */
    @Override
    public Service createService(Service service, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerPostApiCaller<Service>(
                        Service.class, service, SERVICE_CREATE_API_PATH)
                .setOptions(options));
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
    public void deleteService(long apiKey, Options options) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceOwnerDeleteApiCaller(
                        SERVICE_DELETE_API_PATH, apiKey)
                .setOptions(options));
    }


    /**
     * Call <code>/api/service/get/<i>{serviceApiKey}</i></code> API.
     */
    @Override
    public Service getService(long apiKey, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerGetApiCaller<Service>(
                        Service.class, SERVICE_GET_API_PATH, apiKey)
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/get/list} API.
     */
    @Override
    public ServiceListResponse getServiceList(Options options) throws AuthleteApiException
    {
        return getServiceList(0, 0, false, options);
    }


    @Override
    public ServiceListResponse getServiceList(int start, int end, Options options) throws AuthleteApiException
    {
        return getServiceList(start, end, true, options);
    }


    private ServiceListResponse getServiceList(
            final int start, final int end, final boolean rangeGiven, Options options) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<ServiceListResponse>()
        {
            @Override
            public ServiceListResponse call()
            {
                return callGetServiceList(start, end, rangeGiven, options);
            }
        });
    }


    /**
     * Call <code>/service/get/list</code>.
     */
    private ServiceListResponse callGetServiceList(int start, int end, boolean rangeGiven, Options options)
    {
        WebTarget target = getTarget().path(SERVICE_GET_LIST_API_PATH);

        if (rangeGiven)
        {
            target = target.queryParam("start", start).queryParam("end", end);
        }

        Builder builder = wrapWithDpop(target
                .request(APPLICATION_JSON_TYPE), SERVICE_GET_LIST_API_PATH, "GET")
                .header(AUTHORIZATION, mServiceOwnerAuth);

        setCustomRequestHeaders(builder, options);

        return builder.get(ServiceListResponse.class);
    }


    /**
     * Call <code>/api/service/update/<i>{serviceApiKey}</i></code> API.
     */
    @Override
    public Service updateService(final Service service, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerPostApiCaller<Service>(
                        Service.class, service, SERVICE_UPDATE_API_PATH, service.getApiKey())
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/jwks/get} API
     */
    @Override
    public String getServiceJwks(Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_JWKS_GET_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/jwks/get} API
     */
    @Override
    public String getServiceJwks(boolean pretty, boolean includePrivateKeys, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_JWKS_GET_API_PATH)
                .addParam("pretty", pretty)
                .addParam("includePrivateKeys", includePrivateKeys)
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/configuration} API
     */
    @Override
    public String getServiceConfiguration(Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_CONFIGURATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/configuration} API
     */
    @Override
    public String getServiceConfiguration(boolean pretty, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<String>(
                        String.class, SERVICE_CONFIGURATION_API_PATH)
                .addParam("pretty", pretty)
                .setOptions(options));
    }


    /**
     * Call {@code /api/service/configuration} API
     */
    @Override
    public String getServiceConfiguration(ServiceConfigurationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<String>(
                        String.class, request, SERVICE_CONFIGURATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/client/create} API.
     */
    @Override
    public Client createClient(Client client, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<Client>(
                        Client.class, client, CLIENT_CREATE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/client/registration} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientRegister(ClientRegistrationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/client/registration/get} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientGet(ClientRegistrationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_GET_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/client/registration/update} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientUpdate(ClientRegistrationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_UPDATE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/client/registration/delete} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientDelete(ClientRegistrationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_DELETE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call <code>/api/client/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteClient(long clientId, Options options) throws AuthleteApiException
    {
        deleteClient(String.valueOf(clientId), options);
    }


    /**
     * Call <code>/api/client/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteClient(String clientId, Options options) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceDeleteApiCaller(
                        CLIENT_DELETE_API_PATH, clientId)
                .setOptions(options));
    }


    /**
     * Call <code>/api/client/get/<i>{clientId}</i></code> API.
     */
    @Override
    public Client getClient(long clientId, Options options) throws AuthleteApiException
    {
        return getClient(String.valueOf(clientId), options);
    }


    /**
     * Call <code>/api/client/get/<i>{clientId}</i></code> API.
     */
    @Override
    public Client getClient(String clientId, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<Client>(
                        Client.class, CLIENT_GET_API_PATH, clientId)
                .setOptions(options));
    }


    /**
     * Call {@code /api/client/get/list} API.
     */
    @Override
    public ClientListResponse getClientList(Options options) throws AuthleteApiException
    {
        return getClientList(null, 0, 0, false, options);
    }


    @Override
    public ClientListResponse getClientList(String developer, Options options) throws AuthleteApiException
    {
        return getClientList(developer, 0, 0, false, options);
    }


    @Override
    public ClientListResponse getClientList(int start, int end, Options options) throws AuthleteApiException
    {
        return getClientList(null, start, end, true, options);
    }


    @Override
    public ClientListResponse getClientList(String developer, int start, int end, Options options) throws AuthleteApiException
    {
        return getClientList(developer, start, end, true, options);
    }


    private ClientListResponse getClientList(
            final String developer, final int start, final int end, final boolean rangeGiven, Options options) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<ClientListResponse>()
        {
            @Override
            public ClientListResponse call()
            {
                return callGetClientList(developer, start, end, rangeGiven, options);
            }
        });
    }


    private ClientListResponse callGetClientList(String developer, int start, int end, boolean rangeGiven, Options options)
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

        Builder builder = wrapWithDpop(target
                .request(APPLICATION_JSON_TYPE), CLIENT_GET_LIST_API_PATH, "GET")
                .header(AUTHORIZATION, mServiceAuth);

        setCustomRequestHeaders(builder, options);

        return builder.get(ClientListResponse.class);
    }


    /**
     * Call <code>/api/client/update/<i>{clientId}</i></code> API.
     */
    @Override
    public Client updateClient(Client client, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<Client>(
                        Client.class, client, CLIENT_UPDATE_API_PATH, client.getClientId())
                .setOptions(options));
    }



    /**
     * Call <code>/api/client/extension/requestable_scopes/get/<i>{clientId}</i></code> API.
     */
    @Override
    public String[] getRequestableScopes(long clientId, Options options) throws AuthleteApiException
    {
        // Call the API.
        RequestableScopes response = executeApiCall(
                new ServiceGetApiCaller<RequestableScopes>(
                        RequestableScopes.class, REQUESTABLE_SCOPES_GET_API_PATH, clientId)
                .setOptions(options));

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
    public String[] setRequestableScopes(long clientId, String[] scopes, Options options) throws AuthleteApiException
    {
        // Prepare a request body.
        RequestableScopes request = new RequestableScopes().setRequestableScopes(scopes);

        // Call the API.
        RequestableScopes response = executeApiCall(
                new ServicePostApiCaller<RequestableScopes>(
                        RequestableScopes.class, request, REQUESTABLE_SCOPES_UPDATE_API_PATH, clientId)
                .setOptions(options));

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
    public void deleteRequestableScopes(long clientId, Options options) throws AuthleteApiException
    {
        executeApiCall(
                new ServiceDeleteApiCaller(
                        REQUESTABLE_SCOPES_DELETE_API_PATH, clientId)
                .setOptions(options));
    }


    @Override
    public GrantedScopesGetResponse getGrantedScopes(long clientId, String subject, Options options)
    {
        // Prepare a request body.
        GrantedScopesRequest request = new GrantedScopesRequest(subject);

        // Call the API.
        return executeApiCall(
                new ServicePostApiCaller<GrantedScopesGetResponse>(
                        GrantedScopesGetResponse.class, request, GRANTED_SCOPES_GET_API_PATH, clientId)
                .setOptions(options));
    }


    @Override
    public void deleteGrantedScopes(long clientId, String subject, Options options)
    {
        // Prepare a request body.
        GrantedScopesRequest request = new GrantedScopesRequest(subject);

        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request, GRANTED_SCOPES_DELETE_API_PATH, clientId)
                .setOptions(options));
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
    public void deleteClientAuthorization(long clientId, String subject, Options options) throws AuthleteApiException
    {
        // Prepare a request body.
        ClientAuthorizationDeleteRequest request = new ClientAuthorizationDeleteRequest(subject);

        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_AUTHORIZATION_DELETE_API_PATH, clientId)
                .setOptions(options));
    }


    @Override
    public AuthorizedClientListResponse getClientAuthorizationList(ClientAuthorizationGetListRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<AuthorizedClientListResponse>(
                        AuthorizedClientListResponse.class, request, CLIENT_AUTHORIZATION_GET_LIST_API_PATH)
                .setOptions(options));
    }


    @Override
    public void updateClientAuthorization(long clientId, ClientAuthorizationUpdateRequest request, Options options) throws AuthleteApiException
    {
        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_AUTHORIZATION_UPDATE_API_PATH, clientId)
                .setOptions(options));
    }


    @Override
    public ClientSecretRefreshResponse refreshClientSecret(long clientId, Options options) throws AuthleteApiException
    {
        return refreshClientSecret(String.valueOf(clientId), options);
    }


    @Override
    public ClientSecretRefreshResponse refreshClientSecret(String clientIdentifier, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<ClientSecretRefreshResponse>(
                        ClientSecretRefreshResponse.class,
                        CLIENT_SECRET_REFRESH_API_PATH, clientIdentifier)
                .setOptions(options));
    }


    @Override
    public ClientSecretUpdateResponse updateClientSecret(long clientId, String clientSecret, Options options) throws AuthleteApiException
    {
        return updateClientSecret(String.valueOf(clientId), clientSecret, options);
    }


    @Override
    public ClientSecretUpdateResponse updateClientSecret(String clientIdentifier, String clientSecret, Options options) throws AuthleteApiException
    {
        // Prepare a request body. setClientSecret(String) method
        // throws IllegalArgumentException if the given client secret
        // does not comply with the format.
        ClientSecretUpdateRequest request
            = new ClientSecretUpdateRequest().setClientSecret(clientSecret);

        return executeApiCall(
                new ServicePostApiCaller<ClientSecretUpdateResponse>(
                        ClientSecretUpdateResponse.class, request,
                        CLIENT_SECRET_UPDATE_API_PATH, clientIdentifier)
                .setOptions(options));
    }


    /**
     * Call {@code /api/jose/verify} API.
     */
    @Override
    public JoseVerifyResponse verifyJose(JoseVerifyRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<JoseVerifyResponse>(
                        JoseVerifyResponse.class, request, JOSE_VERIFY_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/backchannel/authentication} API.
     */
    @Override
    public BackchannelAuthenticationResponse backchannelAuthentication(
            BackchannelAuthenticationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationResponse>(
                        BackchannelAuthenticationResponse.class, request, BACKCHANNEL_AUTHENTICATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/backchannel/authentication/issue} API.
     */
    @Override
    public BackchannelAuthenticationIssueResponse backchannelAuthenticationIssue(
            BackchannelAuthenticationIssueRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationIssueResponse>(
                        BackchannelAuthenticationIssueResponse.class, request, BACKCHANNEL_AUTHENTICATION_ISSUE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/backchannel/authentication/fail} API.
     */
    @Override
    public BackchannelAuthenticationFailResponse backchannelAuthenticationFail(
            BackchannelAuthenticationFailRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationFailResponse>(
                        BackchannelAuthenticationFailResponse.class, request,
                        BACKCHANNEL_AUTHENTICATION_FAIL_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/backchannel/authentication/complete} API.
     */
    @Override
    public BackchannelAuthenticationCompleteResponse backchannelAuthenticationComplete(
            BackchannelAuthenticationCompleteRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<BackchannelAuthenticationCompleteResponse>(
                        BackchannelAuthenticationCompleteResponse.class, request,
                        BACKCHANNEL_AUTHENTICATION_COMPLETE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/device/authorization} API.
     */
    @Override
    public DeviceAuthorizationResponse deviceAuthorization(DeviceAuthorizationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<DeviceAuthorizationResponse>(
                        DeviceAuthorizationResponse.class, request, DEVICE_AUTHORIZATION_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/device/complete} API.
     */
    @Override
    public DeviceCompleteResponse deviceComplete(DeviceCompleteRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<DeviceCompleteResponse>(
                        DeviceCompleteResponse.class, request, DEVICE_COMPLETE_API_PATH)
                .setOptions(options));
    }


    /**
     * Call {@code /api/device/verification} API.
     */
    @Override
    public DeviceVerificationResponse deviceVerification(DeviceVerificationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<DeviceVerificationResponse>(
                        DeviceVerificationResponse.class, request, DEVICE_VERIFICATION_API_PATH)
                .setOptions(options));
    }


    @Override
    public PushedAuthReqResponse pushAuthorizationRequest(PushedAuthReqRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<PushedAuthReqResponse>(
                        PushedAuthReqResponse.class, request, PUSHED_AUTH_REQ_API_PATH)
                .setOptions(options));
    }


    @Override
    public HskResponse hskCreate(HskCreateRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<HskResponse>(
                        HskResponse.class, request, HSK_CREATE_API_PATH)
                .setOptions(options));
    }


    @Override
    public HskResponse hskDelete(String handle, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<HskResponse>(
                        HskResponse.class,
                        HSK_DELETE_API_PATH, handle)
                .setOptions(options));
    }


    @Override
    public HskResponse hskGet(String handle, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<HskResponse>(
                        HskResponse.class,
                        HSK_GET_API_PATH, handle)
                .setOptions(options));
    }


    @Override
    public HskListResponse hskGetList(Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceGetApiCaller<HskListResponse>(
                        HskListResponse.class,
                        HSK_GET_LIST_API_PATH)
                .setOptions(options));
    }


    @Override
    public Map<String, String> echo(Map<String, String> parameters, Options options) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<Map<String, String>>()
        {
            @Override
            public Map<String, String> call()
            {
                return callEcho(parameters, options);
            }
        });
    }


    private Map<String, String> callEcho(Map<String, String> parameters, Options options)
    {
        WebTarget target = getTarget().path(ECHO_API_PATH);

        if (parameters != null)
        {
            for (Map.Entry<String, String> entry : parameters.entrySet())
            {
                target = target.queryParam(entry.getKey(), entry.getValue());
            }
        }

        // The API does not require any authentication, so the code below
        // does not include '.header(AUTHORIZATION, ...)'.

        Builder builder = target.request(APPLICATION_JSON_TYPE);

        setCustomRequestHeaders(builder, options);

        return builder.get(new GenericType<Map<String, String>>(){});
    }


    @Override
    public GMResponse gm(GMRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<GMResponse>(
                        GMResponse.class, request, GM_API_PATH)
                .setOptions(options));
    }


    @Override
    public void updateClientLockFlag(
            String clientIdentifier, boolean clientLocked, Options options) throws AuthleteApiException
    {
        // Prepare a request body.
        ClientLockFlagUpdateRequest request =
                new ClientLockFlagUpdateRequest().setClientLocked(clientLocked);

        executeApiCall(
                new ServicePostApiCaller<ApiResponse>(
                        ApiResponse.class, request,
                        CLIENT_LOCK_FLAG_UPDATE_API_PATH, clientIdentifier)
                .setOptions(options));
    }


    @Override
    public FederationConfigurationResponse federationConfiguration(
            FederationConfigurationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<FederationConfigurationResponse>(
                        FederationConfigurationResponse.class, request,
                        FEDERATION_CONFIGURATION_API_PATH)
                .setOptions(options));
    }


    @Override
    public FederationRegistrationResponse federationRegistration(
            FederationRegistrationRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<FederationRegistrationResponse>(
                        FederationRegistrationResponse.class, request,
                        FEDERATION_REGISTRATION_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialIssuerMetadataResponse credentialIssuerMetadata(
            CredentialIssuerMetadataRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/metadata API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialIssuerMetadataResponse>(
                        CredentialIssuerMetadataResponse.class, request,
                        VCI_METADATA_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialJwtIssuerMetadataResponse credentialJwtIssuerMetadata(
            CredentialJwtIssuerMetadataRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/jwtissuer API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialJwtIssuerMetadataResponse>(
                        CredentialJwtIssuerMetadataResponse.class, request,
                        VCI_JWT_ISSUER_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialIssuerJwksResponse credentialIssuerJwks(
            CredentialIssuerJwksRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/jwks API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialIssuerJwksResponse>(
                        CredentialIssuerJwksResponse.class, request,
                        VCI_JWKS_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialOfferCreateResponse credentialOfferCreate(
            CredentialOfferCreateRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/offer/create API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialOfferCreateResponse>(
                        CredentialOfferCreateResponse.class, request,
                        VCI_OFFER_CREATE_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialOfferInfoResponse credentialOfferInfo(
            CredentialOfferInfoRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/offer/info API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialOfferInfoResponse>(
                        CredentialOfferInfoResponse.class, request,
                        VCI_OFFER_INFO_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialSingleParseResponse credentialSingleParse(
            CredentialSingleParseRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/single/parse API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialSingleParseResponse>(
                        CredentialSingleParseResponse.class, request,
                        VCI_SINGLE_PARSE_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialSingleIssueResponse credentialSingleIssue(
            CredentialSingleIssueRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/single/issue API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialSingleIssueResponse>(
                        CredentialSingleIssueResponse.class, request,
                        VCI_SINGLE_ISSUE_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialBatchParseResponse credentialBatchParse(
            CredentialBatchParseRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/batch/parse API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialBatchParseResponse>(
                        CredentialBatchParseResponse.class, request,
                        VCI_BATCH_PARSE_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialBatchIssueResponse credentialBatchIssue(
            CredentialBatchIssueRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/batch/issue API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialBatchIssueResponse>(
                        CredentialBatchIssueResponse.class, request,
                        VCI_BATCH_ISSUE_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialDeferredParseResponse credentialDeferredParse(
            CredentialDeferredParseRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/deferred/parse API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialDeferredParseResponse>(
                        CredentialDeferredParseResponse.class, request,
                        VCI_DEFERRED_PARSE_API_PATH)
                .setOptions(options));
    }


    @Override
    public CredentialDeferredIssueResponse credentialDeferredIssue(
            CredentialDeferredIssueRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /vci/deferred/issue API is not available in Authlete 2.x,
        // so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<CredentialDeferredIssueResponse>(
                        CredentialDeferredIssueResponse.class, request,
                        VCI_DEFERRED_ISSUE_API_PATH)
                .setOptions(options));
    }


    @Override
    public IDTokenReissueResponse idTokenReissue(
            IDTokenReissueRequest request, Options options) throws AuthleteApiException
    {
        return executeApiCall(
                new ServicePostApiCaller<IDTokenReissueResponse>(
                        IDTokenReissueResponse.class, request,
                        ID_TOKEN_REISSUE_API_PATH)
                .setOptions(options));
    }


    @Override
    public AuthorizationTicketInfoResponse authorizationTicketInfo(
            AuthorizationTicketInfoRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /auth/authorization/ticket/info API is not available
        // in Authlete 2.x, so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<AuthorizationTicketInfoResponse>(
                        AuthorizationTicketInfoResponse.class, request,
                        AUTH_AUTHORIZATION_TICKET_INFO_API_PATH)
                .setOptions(options));
    }


    @Override
    public AuthorizationTicketUpdateResponse authorizationTicketUpdate(
            AuthorizationTicketUpdateRequest request, Options options) throws AuthleteApiException
    {
        // Note that the /auth/authorization/ticket/update API is not available
        // in Authlete 2.x, so the executeApiCall below will throw an exception.

        return executeApiCall(
                new ServicePostApiCaller<AuthorizationTicketUpdateResponse>(
                        AuthorizationTicketUpdateResponse.class, request,
                        AUTH_AUTHORIZATION_TICKET_UPDATE_API_PATH)
                .setOptions(options));
    }


    @Override
    public TokenCreateBatchResponse tokenCreateBatch(
            TokenCreateRequest[] tokenCreateRequests, boolean dryRun, Options options) throws AuthleteApiException
    {
        throw new AuthleteApiException(
                "This method can't be invoked since the corresponding API is not supported.");
    }


    @Override
    public TokenCreateBatchStatusResponse getTokenCreateBatchStatus(
            String requestId, Options options) throws AuthleteApiException
    {
        throw new AuthleteApiException(
                "This method can't be invoked since the corresponding API is not supported.");
    }
}
