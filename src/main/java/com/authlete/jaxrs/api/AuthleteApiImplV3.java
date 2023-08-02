/*
 * Copyright (C) 2014-2023 Authlete, Inc.
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
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.conf.AuthleteApiVersion;
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
import com.authlete.common.dto.ClientLockFlagUpdateRequest;
import com.authlete.common.dto.ClientRegistrationRequest;
import com.authlete.common.dto.ClientRegistrationResponse;
import com.authlete.common.dto.ClientSecretRefreshResponse;
import com.authlete.common.dto.ClientSecretUpdateRequest;
import com.authlete.common.dto.ClientSecretUpdateResponse;
import com.authlete.common.dto.CredentialBatchIssueRequest;
import com.authlete.common.dto.CredentialBatchIssueResponse;
import com.authlete.common.dto.CredentialBatchParseRequest;
import com.authlete.common.dto.CredentialBatchParseResponse;
import com.authlete.common.dto.CredentialDeferredIssueRequest;
import com.authlete.common.dto.CredentialDeferredIssueResponse;
import com.authlete.common.dto.CredentialDeferredParseRequest;
import com.authlete.common.dto.CredentialDeferredParseResponse;
import com.authlete.common.dto.CredentialIssuerJwksRequest;
import com.authlete.common.dto.CredentialIssuerJwksResponse;
import com.authlete.common.dto.CredentialIssuerMetadataRequest;
import com.authlete.common.dto.CredentialIssuerMetadataResponse;
import com.authlete.common.dto.CredentialOfferCreateRequest;
import com.authlete.common.dto.CredentialOfferCreateResponse;
import com.authlete.common.dto.CredentialOfferInfoRequest;
import com.authlete.common.dto.CredentialOfferInfoResponse;
import com.authlete.common.dto.CredentialSingleIssueRequest;
import com.authlete.common.dto.CredentialSingleIssueResponse;
import com.authlete.common.dto.CredentialSingleParseRequest;
import com.authlete.common.dto.CredentialSingleParseResponse;
import com.authlete.common.dto.DeviceAuthorizationRequest;
import com.authlete.common.dto.DeviceAuthorizationResponse;
import com.authlete.common.dto.DeviceCompleteRequest;
import com.authlete.common.dto.DeviceCompleteResponse;
import com.authlete.common.dto.DeviceVerificationRequest;
import com.authlete.common.dto.DeviceVerificationResponse;
import com.authlete.common.dto.FederationConfigurationRequest;
import com.authlete.common.dto.FederationConfigurationResponse;
import com.authlete.common.dto.FederationRegistrationRequest;
import com.authlete.common.dto.FederationRegistrationResponse;
import com.authlete.common.dto.GMRequest;
import com.authlete.common.dto.GMResponse;
import com.authlete.common.dto.GrantedScopesGetResponse;
import com.authlete.common.dto.HskCreateRequest;
import com.authlete.common.dto.HskListResponse;
import com.authlete.common.dto.HskResponse;
import com.authlete.common.dto.IDTokenReissueRequest;
import com.authlete.common.dto.IDTokenReissueResponse;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.JoseVerifyRequest;
import com.authlete.common.dto.JoseVerifyResponse;
import com.authlete.common.dto.PushedAuthReqRequest;
import com.authlete.common.dto.PushedAuthReqResponse;
import com.authlete.common.dto.RevocationRequest;
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.Service;
import com.authlete.common.dto.ServiceConfigurationRequest;
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
import com.authlete.common.dto.TokenRevokeRequest;
import com.authlete.common.dto.TokenRevokeResponse;
import com.authlete.common.dto.TokenUpdateRequest;
import com.authlete.common.dto.TokenUpdateResponse;
import com.authlete.common.dto.UserInfoIssueRequest;
import com.authlete.common.dto.UserInfoIssueResponse;
import com.authlete.common.dto.UserInfoRequest;
import com.authlete.common.dto.UserInfoResponse;


/**
 * The implementation of {@link AuthleteApi} using JAX-RS 2.0 client API.
 *
 * Supports Authlete API V3.
 *
 * @author Justin Richer
 */
public class AuthleteApiImplV3 extends AuthleteApiJaxrsImpl
{
    private static final String AUTH_AUTHORIZATION_API_PATH                   = "/api/%d/auth/authorization";
    private static final String AUTH_AUTHORIZATION_FAIL_API_PATH              = "/api/%d/auth/authorization/fail";
    private static final String AUTH_AUTHORIZATION_ISSUE_API_PATH             = "/api/%d/auth/authorization/issue";
    private static final String AUTH_TOKEN_API_PATH                           = "/api/%d/auth/token";
    private static final String AUTH_TOKEN_CREATE_API_PATH                    = "/api/%d/auth/token/create";
    private static final String AUTH_TOKEN_DELETE_API_PATH                    = "/api/%d/auth/token/delete/%s";
    private static final String AUTH_TOKEN_FAIL_API_PATH                      = "/api/%d/auth/token/fail";
    private static final String AUTH_TOKEN_GET_LIST_API_PATH                  = "/api/%d/auth/token/get/list";
    private static final String AUTH_TOKEN_ISSUE_API_PATH                     = "/api/%d/auth/token/issue";
    private static final String AUTH_TOKEN_REVOKE_API_PATH                    = "/api/%d/auth/token/revoke";
    private static final String AUTH_TOKEN_UPDATE_API_PATH                    = "/api/%d/auth/token/update";
    private static final String AUTH_REVOCATION_API_PATH                      = "/api/%d/auth/revocation";
    private static final String AUTH_USERINFO_API_PATH                        = "/api/%d/auth/userinfo";
    private static final String AUTH_USERINFO_ISSUE_API_PATH                  = "/api/%d/auth/userinfo/issue";
    private static final String AUTH_INTROSPECTION_API_PATH                   = "/api/%d/auth/introspection";
    private static final String AUTH_INTROSPECTION_STANDARD_API_PATH          = "/api/%d/auth/introspection/standard";
    private static final String SERVICE_CONFIGURATION_API_PATH                = "/api/%d/service/configuration";
    private static final String SERVICE_CREATE_API_PATH                       = "/api/service/create";
    private static final String SERVICE_DELETE_API_PATH                       = "/api/%d/service/delete";
    private static final String SERVICE_GET_API_PATH                          = "/api/%d/service/get";
    private static final String SERVICE_GET_LIST_API_PATH                     = "/api/service/get/list";
    private static final String SERVICE_JWKS_GET_API_PATH                     = "/api/%d/service/jwks/get";
    private static final String SERVICE_UPDATE_API_PATH                       = "/api/%d/service/update";
    private static final String CLIENT_CREATE_API_PATH                        = "/api/%d/client/create";
    private static final String CLIENT_REGISTRATION_API_PATH                  = "/api/%d/client/registration";
    private static final String CLIENT_REGISTRATION_GET_API_PATH              = "/api/%d/client/registration/get";
    private static final String CLIENT_REGISTRATION_UPDATE_API_PATH           = "/api/%d/client/registration/update";
    private static final String CLIENT_REGISTRATION_DELETE_API_PATH           = "/api/%d/client/registration/delete";
    private static final String CLIENT_DELETE_API_PATH                        = "/api/%d/client/delete/%s";
    private static final String CLIENT_GET_API_PATH                           = "/api/%d/client/get/%s";
    private static final String CLIENT_GET_LIST_API_PATH                      = "/api/%d/client/get/list";
    private static final String CLIENT_SECRET_REFRESH_API_PATH                = "/api/%d/client/secret/refresh/%s";
    private static final String CLIENT_SECRET_UPDATE_API_PATH                 = "/api/%d/client/secret/update/%s";
    private static final String CLIENT_UPDATE_API_PATH                        = "/api/%d/client/update/%d";
    private static final String REQUESTABLE_SCOPES_DELETE_API_PATH            = "/api/%d/client/extension/requestable_scopes/delete/%d";
    private static final String REQUESTABLE_SCOPES_GET_API_PATH               = "/api/%d/client/extension/requestable_scopes/get/%d";
    private static final String REQUESTABLE_SCOPES_UPDATE_API_PATH            = "/api/%d/client/extension/requestable_scopes/update/%d";
    private static final String GRANTED_SCOPES_GET_API_PATH                   = "/api/%d/client/granted_scopes/get/%d";
    private static final String GRANTED_SCOPES_DELETE_API_PATH                = "/api/%d/client/granted_scopes/delete/%d";
    private static final String CLIENT_AUTHORIZATION_DELETE_API_PATH          = "/api/%d/client/authorization/delete/%d";
    private static final String CLIENT_AUTHORIZATION_GET_LIST_API_PATH        = "/api/%d/client/authorization/get/list";
    private static final String CLIENT_AUTHORIZATION_UPDATE_API_PATH          = "/api/%d/client/authorization/update/%d";
    private static final String JOSE_VERIFY_API_PATH                          = "/api/%d/jose/verify";
    private static final String BACKCHANNEL_AUTHENTICATION_API_PATH           = "/api/%d/backchannel/authentication";
    private static final String BACKCHANNEL_AUTHENTICATION_COMPLETE_API_PATH  = "/api/%d/backchannel/authentication/complete";
    private static final String BACKCHANNEL_AUTHENTICATION_FAIL_API_PATH      = "/api/%d/backchannel/authentication/fail";
    private static final String BACKCHANNEL_AUTHENTICATION_ISSUE_API_PATH     = "/api/%d/backchannel/authentication/issue";
    private static final String DEVICE_AUTHORIZATION_API_PATH                 = "/api/%d/device/authorization";
    private static final String DEVICE_COMPLETE_API_PATH                      = "/api/%d/device/complete";
    private static final String DEVICE_VERIFICATION_API_PATH                  = "/api/%d/device/verification";
    private static final String PUSHED_AUTH_REQ_API_PATH                      = "/api/%d/pushed_auth_req";
    private static final String HSK_CREATE_API_PATH                           = "/api/%d/hsk/create";
    private static final String HSK_DELETE_API_PATH                           = "/api/%d/hsk/delete/%s";
    private static final String HSK_GET_API_PATH                              = "/api/%d/hsk/get/%s";
    private static final String HSK_GET_LIST_API_PATH                         = "/api/%d/hsk/get/list";
    private static final String ECHO_API_PATH                                 = "/api/misc/echo";
    private static final String GM_API_PATH                                   = "/api/%d/gm";
    private static final String CLIENT_LOCK_FLAG_UPDATE_API_PATH              = "/api/%d/client/lock_flag/update/%s";
    private static final String FEDERATION_CONFIGURATION_API_PATH             = "/api/%d/federation/configuration";
    private static final String FEDERATION_REGISTRATION_API_PATH              = "/api/%d/federation/registration";
    private static final String VCI_API_PATH                                  = "/api/%d/vci/jwks";
    private static final String VCI_METADATA_API_PATH                         = "/api/%d/vci/metadata";
    private static final String VCI_OFFER_CREATE_API_PATH                     = "/api/%d/vci/offer/create";
    private static final String VCI_OFFER_INFO_API_PATH                       = "/api/%d/vci/offer/info";
    private static final String VCI_SINGLE_PARSE_API_PATH                     = "/api/%d/vci/single/parse";
    private static final String VCI_SINGLE_ISSUE_API_PATH                     = "/api/%d/vci/single/issue";
    private static final String VCI_BATCH_PARSE_API_PATH                      = "/api/%d/vci/batch/parse";
    private static final String VCI_BATCH_ISSUE_API_PATH                      = "/api/%d/vci/batch/issue";
    private static final String VCI_DEFERRED_PARSE_API_PATH                   = "/api/%d/vci/deferred/parse";
    private static final String VCI_DEFERRED_ISSUE_API_PATH                   = "/api/%d/vci/deferred/issue";
    private static final String ID_TOKEN_REISSUE_API_PATH                     = "/api/%d/idtoken/reissue";


    private final String mAuth;
    private final Long mServiceId;

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
    public AuthleteApiImplV3(AuthleteConfiguration configuration)
    {
        super(configuration);

        // Authlete API version specified by the configuration.
        AuthleteApiVersion version =
                AuthleteApiVersion.parse(configuration.getApiVersion());

        if (version != AuthleteApiVersion.V3)
        {
            throw new IllegalArgumentException("Configuration must be set to V3 for this implementation.");
        }

        mAuth = createCredentials(configuration);
        if (configuration.getServiceApiKey() != null)
        {
            mServiceId = Long.parseLong(configuration.getServiceApiKey());
        }
        else
        {
            mServiceId = null;
        }
    }


    /**
     * Create an authorization header for the access token.
     */
    private String createCredentials(AuthleteConfiguration configuration)
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
            throw new IllegalArgumentException("V3 API requires an access token, not a key and secret");
        }
    }


    private <TResponse> TResponse callGetApi(
            String path, Class<TResponse> responseClass, Map<String, Object[]> params)
    {
        return callGetApi(mAuth, path, responseClass, params);
    }


    private Void callDeleteApi(String path)
    {
        return callDeleteApi(mAuth, path);
    }


    private <TResponse> TResponse callPostApi(String path, Object request, Class<TResponse> responseClass)
    {
        return callPostApi(mAuth, path, request, responseClass);
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


    private class DeleteApiCaller extends ApiCaller<Void>
    {
        DeleteApiCaller(String path)
        {
            super(Void.class, null, path);
        }


        DeleteApiCaller(String format, Object... args)
        {
            super(Void.class, null, format, args);
        }


        @Override
        public Void call()
        {
            return callDeleteApi(mPath);
        }
    }


    private class GetApiCaller<TResponse> extends ApiCaller<TResponse>
    {
        GetApiCaller(Class<TResponse> responseClass, String path)
        {
            super(responseClass, null, path);
        }


        GetApiCaller(Class<TResponse> responseClass, String format, Object... args)
        {
            super(responseClass, null, format, args);
        }


        @Override
        public TResponse call()
        {
            return callGetApi(mPath, mResponseClass, mParams);
        }
    }


    private class PostApiCaller<TResponse> extends ApiCaller<TResponse>
    {
        PostApiCaller(Class<TResponse> responseClass, Object request, String path)
        {
            super(responseClass, request, path);
        }


        PostApiCaller(Class<TResponse> responseClass, Object request, String format, Object... args)
        {
            super(responseClass, request, format, args);
        }


        @Override
        public TResponse call()
        {
            return callPostApi(mPath, mRequest, mResponseClass);
        }
    }


    /**
     * Call {@code /api/{serviceId}/auth/authorization} API.
     */
    @Override
    public AuthorizationResponse authorization(AuthorizationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<AuthorizationResponse>(
                        AuthorizationResponse.class, request, AUTH_AUTHORIZATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/authorization/fail} API.
     */
    @Override
    public AuthorizationFailResponse authorizationFail(AuthorizationFailRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<AuthorizationFailResponse>(
                        AuthorizationFailResponse.class, request, AUTH_AUTHORIZATION_FAIL_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/authorization/issue} API.
     */
    @Override
    public AuthorizationIssueResponse authorizationIssue(AuthorizationIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<AuthorizationIssueResponse>(
                        AuthorizationIssueResponse.class, request, AUTH_AUTHORIZATION_ISSUE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/token} API.
     */
    @Override
    public TokenResponse token(TokenRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<TokenResponse>(
                        TokenResponse.class, request, AUTH_TOKEN_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/token/create} API.
     */
    @Override
    public TokenCreateResponse tokenCreate(TokenCreateRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<TokenCreateResponse>(
                        TokenCreateResponse.class, request, AUTH_TOKEN_CREATE_API_PATH, mServiceId));
    }


    /**
     * Call <code>/api/{serviceId}/auth/token/delete/<i>{token}</i></code> API.
     */
    @Override
    public void tokenDelete(String token) throws AuthleteApiException
    {
        executeApiCall(
                new DeleteApiCaller(
                        AUTH_TOKEN_DELETE_API_PATH, mServiceId, token));
    }


    /**
     * Call {@code /api/{serviceId}/auth/token/fail} API.
     */
    @Override
    public TokenFailResponse tokenFail(TokenFailRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<TokenFailResponse>(
                        TokenFailResponse.class, request, AUTH_TOKEN_FAIL_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/token/issue} API.
     */
    @Override
    public TokenIssueResponse tokenIssue(TokenIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<TokenIssueResponse>(
                        TokenIssueResponse.class, request, AUTH_TOKEN_ISSUE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/token/revoke} API.
     */
    @Override
    public TokenRevokeResponse tokenRevoke(TokenRevokeRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<TokenRevokeResponse>(
                        TokenRevokeResponse.class, request, AUTH_TOKEN_REVOKE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/token/update} API.
     */
    @Override
    public TokenUpdateResponse tokenUpdate(TokenUpdateRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<TokenUpdateResponse>(
                        TokenUpdateResponse.class, request, AUTH_TOKEN_UPDATE_API_PATH, mServiceId));
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
        return executeApiCall(new AuthleteApiCall<TokenListResponse>()
        {
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
        String path = String.format(AUTH_TOKEN_GET_LIST_API_PATH, mServiceId);

        WebTarget target = getTarget().path(path);

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

        // FIXME: it feels weird that this is in its own space instead of the caller classes, is there a reason for that?
        return wrapWithDpop(target
                .request(APPLICATION_JSON_TYPE), AUTH_TOKEN_GET_LIST_API_PATH, "GET")
                .header(AUTHORIZATION, mAuth)
                .get(TokenListResponse.class);
    }


    /**
     * Call {@code /api/{serviceId}/auth/revocation} API.
     */
    @Override
    public RevocationResponse revocation(RevocationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<RevocationResponse>(
                        RevocationResponse.class, request, AUTH_REVOCATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/userinfo} API.
     */
    @Override
    public UserInfoResponse userinfo(UserInfoRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<UserInfoResponse>(
                        UserInfoResponse.class, request, AUTH_USERINFO_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/userinfo/issue} API.
     */
    @Override
    public UserInfoIssueResponse userinfoIssue(UserInfoIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<UserInfoIssueResponse>(
                        UserInfoIssueResponse.class, request, AUTH_USERINFO_ISSUE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/introspection} API.
     */
    @Override
    public IntrospectionResponse introspection(IntrospectionRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<IntrospectionResponse>(
                        IntrospectionResponse.class, request, AUTH_INTROSPECTION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/auth/introspection/standard} API.
     */
    @Override
    public StandardIntrospectionResponse standardIntrospection(
            StandardIntrospectionRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<StandardIntrospectionResponse>(
                        StandardIntrospectionResponse.class, request, AUTH_INTROSPECTION_STANDARD_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/service/create} API.
     */
    @Override
    public Service createService(Service service) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<Service>(
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
     * Call <code>/api/{serviceId}/service/delete/</code> API.
     */
    @Override
    public void deleteService(long apiKey) throws AuthleteApiException
    {
        executeApiCall(
                new DeleteApiCaller(
                        SERVICE_DELETE_API_PATH, apiKey));
    }


    /**
     * Call <code>/api/{serviceId}/service/get</i></code> API.
     */
    @Override
    public Service getService(long apiKey) throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<Service>(
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
        return executeApiCall(new AuthleteApiCall<ServiceListResponse>()
        {
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

        // FIXME: it feels strange that this doesn't use the caller structures above
        return wrapWithDpop(target
                .request(APPLICATION_JSON_TYPE), SERVICE_GET_LIST_API_PATH, "GET")
                .header(AUTHORIZATION, mAuth)
                .get(ServiceListResponse.class);
    }


    /**
     * Call <code>/api/{serviceId}/service/update/</code> API.
     */
    @Override
    public Service updateService(final Service service) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<Service>(
                        Service.class, service, SERVICE_UPDATE_API_PATH, service.getApiKey()));
    }


    /**
     * Call {@code /api/{serviceId}/service/jwks/get} API
     */
    @Override
    public String getServiceJwks() throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<String>(
                        String.class, SERVICE_JWKS_GET_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/service/jwks/get} API
     */
    @Override
    public String getServiceJwks(boolean pretty, boolean includePrivateKeys) throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<String>(
                        String.class, SERVICE_JWKS_GET_API_PATH, mServiceId)
                .addParam("pretty", pretty)
                .addParam("includePrivateKeys", includePrivateKeys));
    }


    /**
     * Call {@code /api/{serviceId}/service/configuration} API
     */
    @Override
    public String getServiceConfiguration() throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<String>(
                        String.class, SERVICE_CONFIGURATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/service/configuration} API
     */
    @Override
    public String getServiceConfiguration(boolean pretty) throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<String>(
                        String.class, SERVICE_CONFIGURATION_API_PATH, mServiceId)
                .addParam("pretty", pretty));
    }


    /**
     * Call {@code /api/{serviceId}/service/configuration} API
     */
    @Override
    public String getServiceConfiguration(ServiceConfigurationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<String>(
                        String.class, request, SERVICE_CONFIGURATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/client/create} API.
     */
    @Override
    public Client createClient(Client client) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<Client>(
                        Client.class, client, CLIENT_CREATE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/client/registration} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientRegister(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/client/registration/get} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientGet(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_GET_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/client/registration/update} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientUpdate(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_UPDATE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/client/registration/delete} API.
     */
    @Override
    public ClientRegistrationResponse dynamicClientDelete(ClientRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<ClientRegistrationResponse>(
                        ClientRegistrationResponse.class, request, CLIENT_REGISTRATION_DELETE_API_PATH, mServiceId));
    }


    /**
     * Call <code>/api/{serviceId}/client/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteClient(long clientId) throws AuthleteApiException
    {
        deleteClient(String.valueOf(clientId));
    }


    /**
     * Call <code>/api/{serviceId}/client/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteClient(String clientId) throws AuthleteApiException
    {
        executeApiCall(
                new DeleteApiCaller(
                        CLIENT_DELETE_API_PATH, mServiceId, clientId));
    }


    /**
     * Call <code>/api/{serviceId}/client/get/<i>{clientId}</i></code> API.
     */
    @Override
    public Client getClient(long clientId) throws AuthleteApiException
    {
        return getClient(String.valueOf(clientId));
    }


    /**
     * Call <code>/api/{serviceId}/client/get/<i>{clientId}</i></code> API.
     */
    @Override
    public Client getClient(String clientId) throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<Client>(
                        Client.class, CLIENT_GET_API_PATH, mServiceId, clientId));
    }


    /**
     * Call {@code /api/{serviceId}/client/get/list} API.
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
        return executeApiCall(new AuthleteApiCall<ClientListResponse>()
        {
            @Override
            public ClientListResponse call()
            {
                return callGetClientList(developer, start, end, rangeGiven);
            }
        });
    }


    private ClientListResponse callGetClientList(String developer, int start, int end, boolean rangeGiven)
    {
        String path = String.format(CLIENT_GET_LIST_API_PATH, mServiceId);

        WebTarget target = getTarget().path(path);

        if (developer != null)
        {
            // the "developer" query field is deprecated
        }

        if (rangeGiven)
        {
            target = target.queryParam("start", start).queryParam("end", end);
        }

        // FIXME: this seems weird that it's not the same caller structure as others
        return wrapWithDpop(target
                .request(APPLICATION_JSON_TYPE), CLIENT_GET_LIST_API_PATH, "GET")
                .header(AUTHORIZATION, mAuth)
                .get(ClientListResponse.class);
    }


    /**
     * Call <code>/api/{serviceId}/client/update/<i>{clientId}</i></code> API.
     */
    @Override
    public Client updateClient(Client client) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<Client>(
                        Client.class, client, CLIENT_UPDATE_API_PATH, mServiceId, client.getClientId()));
    }



    /**
     * Call <code>/api/{serviceId}/client/extension/requestable_scopes/get/<i>{clientId}</i></code> API.
     */
    @Override
    public String[] getRequestableScopes(long clientId) throws AuthleteApiException
    {
        // Call the API.
        RequestableScopes response = executeApiCall(
                new GetApiCaller<RequestableScopes>(
                        RequestableScopes.class, REQUESTABLE_SCOPES_GET_API_PATH, mServiceId, clientId));

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
                new PostApiCaller<RequestableScopes>(
                        RequestableScopes.class, request, REQUESTABLE_SCOPES_UPDATE_API_PATH, mServiceId, clientId));

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
     * Call <code>/api/{serviceId}/client/extension/requestable_scopes/delete/<i>{clientId}</i></code> API.
     */
    @Override
    public void deleteRequestableScopes(long clientId) throws AuthleteApiException
    {
        executeApiCall(
                new DeleteApiCaller(
                        REQUESTABLE_SCOPES_DELETE_API_PATH, mServiceId, clientId));
    }


    @Override
    public GrantedScopesGetResponse getGrantedScopes(long clientId, String subject)
    {
        // Prepare a request body.
        GrantedScopesRequest request = new GrantedScopesRequest(subject);

        // Call the API.
        return executeApiCall(
                new PostApiCaller<GrantedScopesGetResponse>(
                        GrantedScopesGetResponse.class, request, GRANTED_SCOPES_GET_API_PATH, mServiceId, clientId));
    }


    @Override
    public void deleteGrantedScopes(long clientId, String subject)
    {
        // Prepare a request body.
        GrantedScopesRequest request = new GrantedScopesRequest(subject);

        executeApiCall(
                new PostApiCaller<ApiResponse>(
                        ApiResponse.class, request, GRANTED_SCOPES_DELETE_API_PATH, mServiceId, clientId));
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
                new PostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_AUTHORIZATION_DELETE_API_PATH, mServiceId, clientId));
    }


    @Override
    public AuthorizedClientListResponse getClientAuthorizationList(ClientAuthorizationGetListRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<AuthorizedClientListResponse>(
                        AuthorizedClientListResponse.class, request, CLIENT_AUTHORIZATION_GET_LIST_API_PATH, mServiceId));
    }


    @Override
    public void updateClientAuthorization(long clientId, ClientAuthorizationUpdateRequest request) throws AuthleteApiException
    {
        executeApiCall(
                new PostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_AUTHORIZATION_UPDATE_API_PATH, mServiceId, clientId));
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
                new GetApiCaller<ClientSecretRefreshResponse>(
                        ClientSecretRefreshResponse.class,
                        CLIENT_SECRET_REFRESH_API_PATH, mServiceId, clientIdentifier));
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
                new PostApiCaller<ClientSecretUpdateResponse>(
                        ClientSecretUpdateResponse.class, request,
                        CLIENT_SECRET_UPDATE_API_PATH, mServiceId, clientIdentifier));
    }


    /**
     * Call {@code /api/{serviceId}/jose/verify} API.
     */
    @Override
    public JoseVerifyResponse verifyJose(JoseVerifyRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<JoseVerifyResponse>(
                        JoseVerifyResponse.class, request, JOSE_VERIFY_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/backchannel/authentication} API.
     */
    @Override
    public BackchannelAuthenticationResponse backchannelAuthentication(BackchannelAuthenticationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<BackchannelAuthenticationResponse>(
                        BackchannelAuthenticationResponse.class, request, BACKCHANNEL_AUTHENTICATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/backchannel/authentication/issue} API.
     */
    @Override
    public BackchannelAuthenticationIssueResponse backchannelAuthenticationIssue(BackchannelAuthenticationIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<BackchannelAuthenticationIssueResponse>(
                        BackchannelAuthenticationIssueResponse.class, request, BACKCHANNEL_AUTHENTICATION_ISSUE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/backchannel/authentication/fail} API.
     */
    @Override
    public BackchannelAuthenticationFailResponse backchannelAuthenticationFail(BackchannelAuthenticationFailRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<BackchannelAuthenticationFailResponse>(
                        BackchannelAuthenticationFailResponse.class, request, BACKCHANNEL_AUTHENTICATION_FAIL_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/backchannel/authentication/complete} API.
     */
    @Override
    public BackchannelAuthenticationCompleteResponse backchannelAuthenticationComplete(BackchannelAuthenticationCompleteRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<BackchannelAuthenticationCompleteResponse>(
                        BackchannelAuthenticationCompleteResponse.class, request, BACKCHANNEL_AUTHENTICATION_COMPLETE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/device/authorization} API.
     */
    @Override
    public DeviceAuthorizationResponse deviceAuthorization(DeviceAuthorizationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<DeviceAuthorizationResponse>(
                        DeviceAuthorizationResponse.class, request, DEVICE_AUTHORIZATION_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/device/complete} API.
     */
    @Override
    public DeviceCompleteResponse deviceComplete(DeviceCompleteRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<DeviceCompleteResponse>(
                        DeviceCompleteResponse.class, request, DEVICE_COMPLETE_API_PATH, mServiceId));
    }


    /**
     * Call {@code /api/{serviceId}/device/verification} API.
     */
    @Override
    public DeviceVerificationResponse deviceVerification(DeviceVerificationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<DeviceVerificationResponse>(
                        DeviceVerificationResponse.class, request, DEVICE_VERIFICATION_API_PATH, mServiceId));
    }


    @Override
    public PushedAuthReqResponse pushAuthorizationRequest(PushedAuthReqRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<PushedAuthReqResponse>(
                        PushedAuthReqResponse.class, request, PUSHED_AUTH_REQ_API_PATH, mServiceId));
    }


    @Override
    public HskResponse hskCreate(HskCreateRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<HskResponse>(
                        HskResponse.class, request, HSK_CREATE_API_PATH, mServiceId));
    }


    @Override
    public HskResponse hskDelete(String handle) throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<HskResponse>(
                        HskResponse.class,
                        HSK_DELETE_API_PATH, mServiceId, handle));
    }


    @Override
    public HskResponse hskGet(String handle) throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<HskResponse>(
                        HskResponse.class,
                        HSK_GET_API_PATH, mServiceId, handle));
    }


    @Override
    public HskListResponse hskGetList() throws AuthleteApiException
    {
        return executeApiCall(
                new GetApiCaller<HskListResponse>(
                        HskListResponse.class,
                        HSK_GET_LIST_API_PATH, mServiceId));
    }


    @Override
    public Map<String, String> echo(Map<String, String> parameters) throws AuthleteApiException
    {
        return executeApiCall(new AuthleteApiCall<Map<String, String>>()
        {
            @Override
            public Map<String, String> call()
            {
                return callEcho(parameters);
            }
        });
    }


    private Map<String, String> callEcho(Map<String, String> parameters)
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

        return target
                .request(APPLICATION_JSON_TYPE)
                .get(new GenericType<Map<String, String>>(){});
    }


    @Override
    public GMResponse gm(GMRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<GMResponse>(
                        GMResponse.class, request, GM_API_PATH, mServiceId));
    }


    @Override
    public void updateClientLockFlag(
            String clientIdentifier, boolean clientLocked) throws AuthleteApiException
    {
        // Prepare a request body.
        ClientLockFlagUpdateRequest request = new ClientLockFlagUpdateRequest().setClientLocked(clientLocked);

        executeApiCall(
                new PostApiCaller<ApiResponse>(
                        ApiResponse.class, request, CLIENT_LOCK_FLAG_UPDATE_API_PATH, mServiceId, clientIdentifier));
    }


    @Override
    public FederationConfigurationResponse federationConfiguration(
            FederationConfigurationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<FederationConfigurationResponse>(
                        FederationConfigurationResponse.class, request,
                        FEDERATION_CONFIGURATION_API_PATH, mServiceId));
    }


    @Override
    public FederationRegistrationResponse federationRegistration(
            FederationRegistrationRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<FederationRegistrationResponse>(
                        FederationRegistrationResponse.class, request,
                        FEDERATION_REGISTRATION_API_PATH, mServiceId));
    }


    @Override
    public CredentialIssuerMetadataResponse credentialIssuerMetadata(
            CredentialIssuerMetadataRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialIssuerMetadataResponse>(
                        CredentialIssuerMetadataResponse.class, request,
                        VCI_METADATA_API_PATH, mServiceId));
    }


    @Override public CredentialIssuerJwksResponse credentialIssuerJwks(
            CredentialIssuerJwksRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialIssuerJwksResponse>(
                        CredentialIssuerJwksResponse.class, request,
                        VCI_API_PATH, mServiceId));
    }


    @Override
    public CredentialOfferCreateResponse credentialOfferCreate(
            CredentialOfferCreateRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialOfferCreateResponse>(
                        CredentialOfferCreateResponse.class, request,
                        VCI_OFFER_CREATE_API_PATH, mServiceId));
    }


    @Override
    public CredentialOfferInfoResponse credentialOfferInfo(
            CredentialOfferInfoRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialOfferInfoResponse>(
                        CredentialOfferInfoResponse.class, request,
                        VCI_OFFER_INFO_API_PATH, mServiceId));
    }


    @Override
    public CredentialSingleParseResponse credentialSingleParse(
            CredentialSingleParseRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialSingleParseResponse>(
                        CredentialSingleParseResponse.class, request,
                        VCI_SINGLE_PARSE_API_PATH, mServiceId));
    }


    @Override
    public CredentialSingleIssueResponse credentialSingleIssue(
            CredentialSingleIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialSingleIssueResponse>(
                        CredentialSingleIssueResponse.class, request,
                        VCI_SINGLE_ISSUE_API_PATH, mServiceId));
    }


    @Override
    public CredentialBatchParseResponse credentialBatchParse(
            CredentialBatchParseRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialBatchParseResponse>(
                        CredentialBatchParseResponse.class, request,
                        VCI_BATCH_PARSE_API_PATH, mServiceId));
    }


    @Override
    public CredentialBatchIssueResponse credentialBatchIssue(
            CredentialBatchIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialBatchIssueResponse>(
                        CredentialBatchIssueResponse.class, request,
                        VCI_BATCH_ISSUE_API_PATH, mServiceId));
    }


    @Override
    public CredentialDeferredParseResponse credentialDeferredParse(
            CredentialDeferredParseRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialDeferredParseResponse>(
                        CredentialDeferredParseResponse.class, request,
                        VCI_DEFERRED_PARSE_API_PATH, mServiceId));
    }


    @Override
    public CredentialDeferredIssueResponse credentialDeferredIssue(
            CredentialDeferredIssueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<CredentialDeferredIssueResponse>(
                        CredentialDeferredIssueResponse.class, request,
                        VCI_DEFERRED_ISSUE_API_PATH, mServiceId));
    }


    @Override
    public IDTokenReissueResponse idTokenReissue(
            IDTokenReissueRequest request) throws AuthleteApiException
    {
        return executeApiCall(
                new PostApiCaller<IDTokenReissueResponse>(
                        IDTokenReissueResponse.class, request,
                        ID_TOKEN_REISSUE_API_PATH, mServiceId));
    }
}
