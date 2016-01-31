/*
 * Copyright (C) 2014-2016 Authlete, Inc.
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
import java.util.List;
import java.util.Map;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.ResponseProcessingException;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.conf.AuthleteConfiguration;
import com.authlete.common.dto.AuthorizationFailRequest;
import com.authlete.common.dto.AuthorizationFailResponse;
import com.authlete.common.dto.AuthorizationIssueRequest;
import com.authlete.common.dto.AuthorizationIssueResponse;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import com.authlete.common.dto.Client;
import com.authlete.common.dto.ClientListResponse;
import com.authlete.common.dto.IntrospectionRequest;
import com.authlete.common.dto.IntrospectionResponse;
import com.authlete.common.dto.RevocationRequest;
import com.authlete.common.dto.RevocationResponse;
import com.authlete.common.dto.Service;
import com.authlete.common.dto.ServiceListResponse;
import com.authlete.common.dto.TokenCreateRequest;
import com.authlete.common.dto.TokenCreateResponse;
import com.authlete.common.dto.TokenFailRequest;
import com.authlete.common.dto.TokenFailResponse;
import com.authlete.common.dto.TokenIssueRequest;
import com.authlete.common.dto.TokenIssueResponse;
import com.authlete.common.dto.TokenRequest;
import com.authlete.common.dto.TokenResponse;
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
    private interface AuthleteApiCall<TResponse>
    {
        TResponse call();
    }


    private static final String AUTH_AUTHORIZATION_API_PATH       = "/api/auth/authorization";
    private static final String AUTH_AUTHORIZATION_FAIL_API_PATH  = "/api/auth/authorization/fail";
    private static final String AUTH_AUTHORIZATION_ISSUE_API_PATH = "/api/auth/authorization/issue";
    private static final String AUTH_TOKEN_API_PATH               = "/api/auth/token";
    private static final String AUTH_TOKEN_CREATE_API_PATH        = "/api/auth/token/create";
    private static final String AUTH_TOKEN_FAIL_API_PATH          = "/api/auth/token/fail";
    private static final String AUTH_TOKEN_ISSUE_API_PATH         = "/api/auth/token/issue";
    private static final String AUTH_REVOCATION_API_PATH          = "/api/auth/revocation";
    private static final String AUTH_USERINFO_API_PATH            = "/api/auth/userinfo";
    private static final String AUTH_USERINFO_ISSUE_API_PATH      = "/api/auth/userinfo/issue";
    private static final String AUTH_INTROSPECTION_API_PATH       = "/api/auth/introspection";
    private static final String SERVICE_CONFIGURATION_API_PATH    = "/api/service/configuration";
    private static final String SERVICE_CREATE_API_PATH           = "/api/service/create";
    private static final String SERVICE_DELETE_API_PATH           = "/api/service/delete/%d";
    private static final String SERVICE_GET_API_PATH              = "/api/service/get/%d";
    private static final String SERVICE_GET_LIST_API_PATH         = "/api/service/get/list";
    private static final String SERVICE_JWKS_GET_API_PATH         = "/api/service/jwks/get";
    private static final String SERVICE_UPDATE_API_PATH           = "/api/service/update/%d";
    private static final String CLIENT_CREATE_API_PATH            = "/api/client/create";
    private static final String CLIENT_DELETE_API_PATH            = "/api/client/delete/%d";
    private static final String CLIENT_GET_API_PATH               = "/api/client/get/%d";
    private static final String CLIENT_GET_LIST_API_PATH          = "/api/client/get/list";
    private static final String CLIENT_UPDATE_API_PATH            = "/api/client/update/%d";


    private final WebTarget mTarget;
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
        if (configuration == null)
        {
            throw new IllegalArgumentException("configuration is null.");
        }

        mTarget           = ClientBuilder.newClient().target(configuration.getBaseUrl());
        mServiceOwnerAuth = createServiceOwnerCredentials(configuration).format();
        mServiceAuth      = createServiceCredentials(configuration).format();
    }


    /**
     * Create a {@link BasicCredentials} for the service owner.
     */
    private BasicCredentials createServiceOwnerCredentials(AuthleteConfiguration configuration)
    {
        String key    = configuration.getServiceOwnerApiKey();
        String secret = configuration.getServiceOwnerApiSecret();

        return new BasicCredentials(key, secret);
    }


    /**
     * Create a {@link BasicCredentials} for the service.
     */
    private BasicCredentials createServiceCredentials(AuthleteConfiguration configuration)
    {
        String key    = configuration.getServiceApiKey();
        String secret = configuration.getServiceApiSecret();

        return new BasicCredentials(key, secret);
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
        if (response.hasEntity())
        {
            // Get the response body.
            responseBody = extractResponseBody(response);
        }

        // Response headers.
        Map<String, List<String>> headers = response.getStringHeaders();

        // Create an exception with HTTP response information.
        return new AuthleteApiException(message, cause, statusCode, statusMessage, responseBody, headers);
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


    private <TResponse> TResponse callGetApi(String auth, String path, Class<TResponse> responseClass)
    {
        return mTarget
                .path(path)
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, auth)
                .get(responseClass);
    }


    private <TResponse> TResponse callServiceOwnerGetApi(String path, Class<TResponse> responseClass)
    {
        return callGetApi(mServiceOwnerAuth, path, responseClass);
    }


    private <TResponse> TResponse callServiceGetApi(String path, Class<TResponse> responseClass)
    {
        return callGetApi(mServiceAuth, path, responseClass);
    }


    private Void callDeleteApi(String auth, String path)
    {
        mTarget
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
        return mTarget
                .path(path)
                .request(APPLICATION_JSON_TYPE)
                .header(AUTHORIZATION, auth)
                .post(Entity.entity(request, APPLICATION_JSON_TYPE), responseClass);
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
            return callServiceOwnerGetApi(mPath, mResponseClass);
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
            return callServiceGetApi(mPath, mResponseClass);
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
     * Call {@code /api/service/create} API.
     */
    @Override
    public Service createServie(Service service) throws AuthleteApiException
    {
        return executeApiCall(
                new ServiceOwnerPostApiCaller<Service>(
                        Service.class, service, SERVICE_CREATE_API_PATH));
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
        WebTarget target = mTarget.path(SERVICE_GET_LIST_API_PATH);

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
        WebTarget target = mTarget.path(CLIENT_GET_LIST_API_PATH);

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
}
