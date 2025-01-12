/*
 * Copyright (C) 2014-2025 Authlete, Inc.
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


import static javax.ws.rs.core.HttpHeaders.ACCEPT;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.HttpHeaders.CONTENT_TYPE;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON_TYPE;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.Map.Entry;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.client.ResponseProcessingException;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.api.Options;
import com.authlete.common.api.Settings;
import com.authlete.common.conf.AuthleteConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


public abstract class AuthleteApiJaxrsImpl implements AuthleteApi
{
    // "application/json;charset=UTF-8"
    private static final MediaType JSON_UTF8_TYPE = APPLICATION_JSON_TYPE.withCharset("UTF-8");


    protected interface AuthleteApiCall<TResponse>
    {
        TResponse call();
    }


    private final String mBaseUrl;
    private final Settings mSettings;
    private javax.ws.rs.client.Client mJaxRsClient;

    private Object mConnectionTimeoutLock = new Object();
    private int mCurrentConnectionTimeout;

    private Object mReadTimeoutLock = new Object();
    private int mCurrentReadTimeout;

    private ClientBuilder jaxRsClientBuilder;

    private JWK mDpopJwk;
    private JWSSigner mJwsSigner;


    /**
     * The constructor with an instance of {@link AuthleteConfiguration}.
     *
     * <p>
     * The existence of a constructor of this type is a required by
     * {@link com.authlete.common.api.AuthleteApiFactory AuthleteApiFactory}.
     * </p>
     *
     * @param configuration
     *            An instance of {@link AuthleteConfiguration}.
     */
    public AuthleteApiJaxrsImpl(AuthleteConfiguration configuration)
    {
        if (configuration == null)
        {
            throw new IllegalArgumentException("configuration is null.");
        }

        mBaseUrl = configuration.getBaseUrl();
        extractDpop(configuration); // this has to be done before the credentials calls
        mSettings = new Settings();
    }


    private void extractDpop(AuthleteConfiguration configuration)
    {
        if (configuration.getDpopKey() != null)
        {
            try
            {
                mDpopJwk = JWK.parse(configuration.getDpopKey());
                if (mDpopJwk.getAlgorithm() == null)
                {
                    throw new IllegalArgumentException("DPoP JWK must contain an 'alg' field.");
                }
                mJwsSigner = new DefaultJWSSignerFactory().createJWSSigner(mDpopJwk);
            }
            catch (ParseException | JOSEException e)
            {
                throw new IllegalArgumentException("DPoP JWK is not valid.");
            }
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
        if (getJaxRsClientBuilder() != null)
        {
            // if we have a builder configured, use it
            return getJaxRsClientBuilder().build();
        }
        else
        {
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

        // ----------------------------------------------------------------------
        // Note that there was no standardized way to set the connection timeout
        // before JAX-RS API 2.1 (Java EE 8) (cf. ClientBuilder.connectTimeout).
        // ----------------------------------------------------------------------

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

        // ----------------------------------------------------------------------
        // Note that there was no standardized way to set the read timeout
        // before JAX-RS API 2.1 (Java EE 8) (cf. ClientBuilder.readTimeout).
        // ----------------------------------------------------------------------

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


    protected WebTarget getTarget()
    {
        return getJaxRsClient().target(mBaseUrl);
    }


    protected Invocation.Builder wrapWithDpop(Invocation.Builder target, String path, String method)
    {
        if (mDpopJwk != null)
        {
            String htu = mBaseUrl + path;

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(mDpopJwk).build();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim("htm", method)
                    .claim("htu", htu)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(new Date())
                    .build();

            JWSObject dpop = new SignedJWT(header, claims);

            try
            {
                dpop.sign(mJwsSigner);
            }
            catch (JOSEException e)
            {
                throw createApiException(e, null); // TODO: should this be a better message?
            }

            return target.header("DPoP", dpop.serialize());
        }
        else
        {
            // no DPoP configuration, just pass through the original target
            return target;
        }
    }


    /**
     * Execute an Authlete API call.
     */
    protected <TResponse> TResponse executeApiCall(AuthleteApiCall<TResponse> apiCall) throws AuthleteApiException
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
            statusCode = type.getStatusCode();
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


    protected <TResponse> TResponse callGetApi(
            String auth, String path, Class<TResponse> responseClass, Map<String, Object[]> params, Options options)
    {
        WebTarget webTarget = getTarget().path(path);

        if (params != null)
        {
            for (Map.Entry<String, Object[]> param : params.entrySet())
            {
                webTarget = webTarget.queryParam(param.getKey(), param.getValue());
            }
        }

        Builder builder = wrapWithDpop(webTarget.request(APPLICATION_JSON_TYPE), path, "GET")
                .header(AUTHORIZATION, auth);

        setCustomRequestHeaders(builder, options);

        return builder.get(responseClass);
    }


    protected Void callDeleteApi(String auth, String path, Options options)
    {
        Builder builder = wrapWithDpop(getTarget()
                .path(path)
                .request(), path, "DELETE")
                .header(AUTHORIZATION, auth);

        setCustomRequestHeaders(builder, options);

        builder.delete();

        return null;
    }


    protected <TResponse> TResponse callPostApi(
            String auth, String path, Object request, Class<TResponse> responseClass, Options options)
    {
        Builder builder = wrapWithDpop(getTarget()
                .path(path)
                .request(APPLICATION_JSON_TYPE), path, "POST")
                .header(AUTHORIZATION, auth);

        setCustomRequestHeaders(builder, options);

        return builder.post(Entity.entity(request, JSON_UTF8_TYPE), responseClass);
    }


    public ClientBuilder getJaxRsClientBuilder()
    {
        return jaxRsClientBuilder;
    }


    public void setJaxRsClientBuilder(ClientBuilder jaxRsClientBuilder)
    {
        this.jaxRsClientBuilder = jaxRsClientBuilder;
    }


    @Override
    public Settings getSettings()
    {
        return mSettings;
    }


    protected boolean isDpopEnabled()
    {
        return mDpopJwk != null;
    }


    protected void setCustomRequestHeaders(Builder builder, Options options)
    {
        if (options == null)
        {
            return;
        }

        // Custom request headers.
        Map<String, String> headers = options.getHeaders();

        if (headers == null)
        {
            // No custom request header is specified.
            return;
        }

        // Add each custom request header to the builder.
        for (Entry<String, String> e : headers.entrySet())
        {
            // The key of the header.
            String key = e.getKey();

            // Some header keys are reserved.
            if (isReservedRequestHeader(key))
            {
                continue;
            }

            builder.header(key, e.getValue());
        }
    }


    private static boolean isReservedRequestHeader(String key)
    {
        return key.equalsIgnoreCase(ACCEPT) ||
               key.equalsIgnoreCase(AUTHORIZATION) ||
               key.equalsIgnoreCase(CONTENT_TYPE);
    }
}
