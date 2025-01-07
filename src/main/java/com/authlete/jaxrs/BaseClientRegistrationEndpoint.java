/*
 * Copyright (C) 2019-2025 Authlete, Inc.
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
package com.authlete.jaxrs;


import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.Options;


/**
 * A base class for dynamic client registration and dynamic client
 * registration management endpoints.
 *
 * @since 2.17
 *
 * @see <a href="https://tools.ietf.org/html/rfc7591">RFC 7591</a>
 *
 * @see <a href="https://tools.ietf.org/html/rfc7592">RFC 7592</a>
 *
 * @see <a href="https://openid.net/specs/openid-connect-registration-1_0.html"
 *      >OpenID Connect Dynamic Client Registration</a>
 */
public class BaseClientRegistrationEndpoint extends BaseEndpoint
{
    /**
     * Handle a client registration request. This method is an alias of {@link
     * #handleGet(AuthleteApi, String, String, Options) handleRegister}{@code
     * (api, json, authorization, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param json
     *         The serialized JSON body of the client registration request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handleRegister(
            AuthleteApi api,
            String json,
            String authorization)
    {
        return handleRegister(api, json, authorization, null);
    }


    /**
     * Handle a client registration request.
     *
     * <p>
     * This method internally creates a {@link ClientRegistrationRequestHandler}
     * instance and calls its {@link ClientRegistrationRequestHandler#handleRegister(String, String, Options) handle()}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code ClientRegistrationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException) onError()}
     * method with the exception. The default implementation of {@code onError()}
     * does nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method of
     * the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param json
     *         The serialized JSON body of the client registration request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @param options
     *         The request options for the {@code /api/client/registration} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handleRegister(
            AuthleteApi api,
            String json,
            String authorization,
            Options options)
    {
        try
        {
            ClientRegistrationRequestHandler handler = new ClientRegistrationRequestHandler(api);

            return handler.handleRegister(json, authorization, options);
        }
        catch (WebApplicationException e)
        {
            onError(e);

            return e.getResponse();
        }
    }


    /**
     * Handle a client registration management get request. This method is an alias
     * of {@link #handleGet(AuthleteApi, String, String, Options) handle}{@code
     * (api, clientId, authorization, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param clientId
     *         The client ID as determined by the incoming request. You will
     *         commonly parse this from the incoming request URL as a path
     *         component. If your Service has its {@code registrationManagementEndpoint}
     *         property set, Authlete will add the client ID as a path parameter
     *         to this URI automatically.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handleGet(
            AuthleteApi api,
            String clientId,
            String authorization)
    {
        return handleGet(api, clientId, authorization, null);
    }


    /**
     * Handle a client registration management get request.
     *
     * <p>
     * This method internally creates a {@link ClientRegistrationRequestHandler}
     * instance and calls its {@link ClientRegistrationRequestHandler#handleGet(String, String, Options) handle()}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code ClientRegistrationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * does nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method of
     * the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param clientId
     *         The client ID as determined by the incoming request. You will
     *         commonly parse this from the incoming request URL as a path
     *         component. If your Service has its {@code registrationManagementEndpoint}
     *         property set, Authlete will add the client ID as a path parameter
     *         to this URI automatically.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @param options
     *         The request options for the {@code /api/client/registration} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handleGet(
            AuthleteApi api,
            String clientId,
            String authorization,
            Options options)
    {
        try
        {
            ClientRegistrationRequestHandler handler = new ClientRegistrationRequestHandler(api);

            return handler.handleGet(clientId, authorization, options);
        }
        catch (WebApplicationException e)
        {
            onError(e);

            return e.getResponse();
        }
    }


    /**
     * Handle a client registration management update request. This method is an
     * alias of the {@link #handleUpdate(AuthleteApi, String, String, String, Options)
     * handleUpdate}{@code (api, clientId, json, authorization, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param clientId
     *         The client ID as determined by the incoming request. You will
     *         commonly parse this from the incoming request URL as a path
     *         component. If your Service has its {@code registrationManagementEndpoint}
     *         property set, Authlete will add the client ID as a path parameter
     *         to this URI automatically.
     *
     * @param json
     *         The serialized JSON body of the client update request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handleUpdate(
            AuthleteApi api,
            String clientId,
            String json,
            String authorization)
    {
        return handleUpdate(api, clientId, json, authorization, null);
    }


    /**
     * Handle a client registration management update request.
     *
     * <p>
     * This method internally creates a {@link ClientRegistrationRequestHandler}
     * instance and calls its
     * {@link ClientRegistrationRequestHandler#handleUpdate(String, String, String) handle()}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code ClientRegistrationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * does nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method of
     * the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param clientId
     *         The client ID as determined by the incoming request. You will
     *         commonly parse this from the incoming request URL as a path
     *         component. If your Service has its {@code registrationManagementEndpoint}
     *         property set, Authlete will add the client ID as a path parameter
     *         to this URI automatically.
     *
     * @param json
     *         The serialized JSON body of the client update request.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @param options
     *         The request options for the {@code /api/client/registration} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handleUpdate(
            AuthleteApi api,
            String clientId,
            String json,
            String authorization,
            Options options)
    {
        try
        {
            ClientRegistrationRequestHandler handler = new ClientRegistrationRequestHandler(api);

            return handler.handleUpdate(clientId, json, authorization, options);
        }
        catch (WebApplicationException e)
        {
            onError(e);

            return e.getResponse();
        }
    }


    /**
     * Handle a client registration management delete request. This method is an
     * alias of {@link #handleDelete(AuthleteApi, String, String, Options) handle}{@code
     * (api, clientId, authorization, null)}.
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param clientId
     *         The client ID as determined by the incoming request. You will
     *         commonly parse this from the incoming request URL as a path
     *         component. If your Service has its {@code registrationManagementEndpoint}
     *         property set, Authlete will add the client ID as a path parameter
     *         to this URI automatically.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @return
     *         A response that should be returned to the client application.
     */
    public Response handleDelete(
            AuthleteApi api,
            String clientId,
            String authorization)
    {
        return handleDelete(api, clientId, authorization, null);
    }


    /**
     * Handle a client registration management delete request.
     *
     * <p>
     * This method internally creates a {@link ClientRegistrationRequestHandler}
     * instance and calls its
     * {@link ClientRegistrationRequestHandler#handleDelete(String, String) handle()}
     * method. Then, this method uses the value returned from the {@code handle()}
     * method as a response from this method.
     * </p>
     *
     * <p>
     * When {@code ClientRegistrationRequestHandler.handle()} method raises a {@link
     * WebApplicationException}, this method calls {@link #onError(WebApplicationException)
     * onError()} method with the exception. The default implementation of {@code onError()}
     * does nothing. You can override the method as necessary. After calling
     * {@code onError()} method, this method calls {@code getResponse()} method of
     * the exception and uses the returned value as a response from this method.
     * </p>
     *
     * @param api
     *         An implementation of {@link AuthleteApi}.
     *
     * @param clientId
     *         The client ID as determined by the incoming request. You will
     *         commonly parse this from the incoming request URL as a path
     *         component. If your Service has its {@code registrationManagementEndpoint}
     *         property set, Authlete will add the client ID as a path parameter
     *         to this URI automatically.
     *
     * @param authorization
     *         The value of {@code Authorization} header of the registration request.
     *         This is optional.
     *
     * @param options
     *         The request options for the {@code /api/client/registration} API.
     *
     * @return
     *         A response that should be returned to the client application.
     *
     * @since 2.82
     */
    public Response handleDelete(
            AuthleteApi api,
            String clientId,
            String authorization,
            Options options)
    {
        try
        {
            ClientRegistrationRequestHandler handler = new ClientRegistrationRequestHandler(api);

            return handler.handleDelete(clientId, authorization);
        }
        catch (WebApplicationException e)
        {
            onError(e);

            return e.getResponse();
        }
    }
}
