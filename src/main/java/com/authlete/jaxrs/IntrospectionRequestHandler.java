/*
 * Copyright (C) 2017-2023 Authlete, Inc.
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


import java.io.Serializable;
import java.net.URI;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import com.authlete.common.api.AuthleteApi;
import com.authlete.common.dto.StandardIntrospectionResponse;
import com.authlete.common.dto.StandardIntrospectionResponse.Action;
import com.authlete.common.types.JWEAlg;
import com.authlete.common.types.JWEEnc;
import com.authlete.common.types.JWSAlg;


/**
 * Handler for token introspection requests
 * (<a href="https://tools.ietf.org/html/rfc7662">RFC 7662</a>).
 *
 * <p>
 * In an implementation of introspection endpoint, call {@link
 * #handle(MultivaluedMap) handle()} method and use the response
 * as the response from the endpoint to the resource server.
 * {@code handle()} method calls Authlete's {@code
 * /api/auth/introspection/standard} API, receives a response
 * from the API, and dispatches processing according to the
 * {@code action} parameter in the response.
 * </p>
 *
 * @since 2.2
 *
 * @author Takahiko Kawasaki
 * @author Hideki Ikeda
 */
public class IntrospectionRequestHandler extends BaseHandler
{
    /**
     * Parameters passed to the {@link IntrospectionRequestHandler#handle(Params)}
     * method.
     *
     * @since 2.63
     */
    public static class Params implements Serializable
    {
        private static final long serialVersionUID = 1L;


        private MultivaluedMap<String, String> parameters;
        private boolean withHiddenProperties;
        private String httpAcceptHeader;
        private URI rsUri;
        private JWSAlg introspectionSignAlg;
        private JWEAlg introspectionEncryptionAlg;
        private JWEEnc introspectionEncryptionEnc;
        private String sharedKeyForSign;
        private String sharedKeyForEncryption;
        private String publicKeyForEncryption;


        /**
         * Get the request parameters of the introspection request.
         *
         * @return
         *         The request parameters of the introspection request.
         */
        public MultivaluedMap<String, String> getParameters()
        {
            return parameters;
        }


        /**
         * Set the request parameters of the introspection request.
         *
         * @param parameters
         *         The request parameters of the introspection request.
         *
         * @return
         *         {@code this} object.
         */
        public Params setParameters(MultivaluedMap<String, String> parameters)
        {
            this.parameters = parameters;

            return this;
        }


        /**
         * Get the flag which indicates whether to include hidden properties
         * associated with the token in the output.
         *
         * @return
         *         {@code true} if hidden properties are included in
         *         the output.
         */
        public boolean isWithHiddenProperties()
        {
            return withHiddenProperties;
        }


        /**
         * Set the flag which indicates whether to include hidden properties
         * associated with the token in the output.
         *
         * @param with
         *         {@code true} if hidden properties are included in
         *         the output.
         *
         * @return
         *         {@code this} object.
         */
        public Params setWithHiddenProperties(boolean with)
        {
            this.withHiddenProperties = with;

            return this;
        }


        /**
         * Get the URI of the resource server making the introspection
         * request.
         *
         * @return The URI of the resource server making the introspection
         *         request.
         */
        public URI getRsUri()
        {
            return rsUri;
        }


        /**
         * Set the URI of the resource server making the introspection
         * request.
         *
         * @param rsUri
         *         The URI of the resource server making the introspection
         *         request.
         *
         * @return
         *         {@code this} object.
         */
        public Params setRsUri(URI uri)
        {
            this.rsUri = uri;

            return this;
        }


        /**
         * Get the value of the HTTP {@code Accept} header in the introspection
         * request.
         *
         * @return
         *         The value of the HTTP {@code Accept} header in the
         *         introspection request.
         */
        public String getHttpAcceptHeader()
        {
            return httpAcceptHeader;
        }


        /**
         * Set the value of the HTTP {@code Accept} header in the introspection
         * request.
         *
         * @param header
         *         The value of the HTTP {@code Accept} header in the
         *         introspection request.
         *
         * @return
         *         {@code this} object.
         */
        public Params setHttpAcceptHeader(String header)
        {
            this.httpAcceptHeader = header;

            return this;
        }


        /**
         * Get the JWS {@code alg} algorithm for signing the introspection
         * response. This property corresponds to {@code introspection_signed_response_alg}
         * defined in "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response#section-6">
         * 6. Client Metadata</a>" of "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response">
         * JWT Response for OAuth Token Introspection</a>".
         *
         * @return
         *         The JWS {@code alg} algorithm for signing the introspection
         *         response.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public JWSAlg getIntrospectionSignAlg()
        {
            return introspectionSignAlg;
        }


        /**
         * Set the JWS {@code alg} algorithm for signing the introspection
         * response. This property corresponds to {@code introspection_signed_response_alg}
         * defined in "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response#section-6">
         * 6. Client Metadata</a>" of "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response">
         * JWT Response for OAuth Token Introspection</a>".
         *
         * @param alg
         *         The JWS {@code alg} algorithm for signing the introspection
         *         response.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public Params setIntrospectionSignAlg(JWSAlg alg)
        {
            this.introspectionSignAlg = alg;

            return this;
        }


        /**
         * Get the JWE {@code alg} algorithm for encrypting the introspection
         * response. This property corresponds to {@code introspection_encrypted_response_alg}
         * defined in "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response#section-6">
         * 6. Client Metadata</a>" of "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response">
         * JWT Response for OAuth Token Introspection</a>".
         *
         * @return
         *         The JWE {@code alg} algorithm for encrypting the
         *         introspection response.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public JWEAlg getIntrospectionEncryptionAlg()
        {
            return introspectionEncryptionAlg;
        }


        /**
         * Set the JWE {@code alg} algorithm for encrypting the introspection
         * response. This property corresponds to {@code introspection_encrypted_response_alg}
         * defined in "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response#section-6">
         * 6. Client Metadata</a>" of "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response">
         * JWT Response for OAuth Token Introspection</a>".
         *
         * @param alg
         *         The JWE {@code alg} algorithm for encrypting the
         *         introspection response.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public Params setIntrospectionEncryptionAlg(JWEAlg alg)
        {
            this.introspectionEncryptionAlg = alg;

            return this;
        }


        /**
         * Get the JWE {@code enc} algorithm for encrypting the introspection
         * response. This property corresponds to {@code introspection_encrypted_response_enc}
         * defined in "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response#section-6">
         * 6. Client Metadata</a>" of "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response">
         * JWT Response for OAuth Token Introspection</a>".
         *
         * @return
         *         The JWE {@code enc} algorithm for encrypting the introspection
         *         response.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public JWEEnc getIntrospectionEncryptionEnc()
        {
            return introspectionEncryptionEnc;
        }


        /**
         * Set the JWE {@code enc} algorithm for encrypting the introspection
         * response. This property corresponds to {@code introspection_encrypted_response_enc}
         * defined in "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response#section-6">
         * 6. Client Metadata</a>" of "<a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response">
         * JWT Response for OAuth Token Introspection</a>".
         *
         * @param enc
         *         The JWE {@code enc} algorithm for encrypting the introspection
         *         response.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public Params setIntrospectionEncryptionEnc(JWEEnc enc)
        {
            this.introspectionEncryptionEnc = enc;

            return this;
        }


        /**
         * Get the shared key for signing the introspection response with
         * a symmetric algorithm.
         *
         * @return
         *         The shared key for signing the introspection response
         *         with a symmetric algorithm.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public String getSharedKeyForSign()
        {
            return sharedKeyForSign;
        }


        /**
         * Set the shared key for signing the introspection response with
         * a symmetric algorithm.
         *
         * @param key
         *         The shared key for signing the introspection response
         *         with a symmetric algorithm.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public Params setSharedKeyForSign(String key)
        {
            this.sharedKeyForSign = key;

            return this;
        }


        /**
         * Get the shared key for encrypting the introspection response
         * with a symmetric algorithm.
         *
         * @return
         *         The shared key for encrypting the introspection response
         *         with a symmetric algorithm.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public String getSharedKeyForEncryption()
        {
            return sharedKeyForEncryption;
        }


        /**
         * Set the shared key for encrypting the introspection response
         * with a symmetric algorithm.
         *
         * @param key
         *         The shared key for encrypting the introspection response
         *         with a symmetric algorithm.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public Params setSharedKeyForEncryption(String key)
        {
            this.sharedKeyForEncryption = key;

            return this;
        }


        /**
         * Get the public key for encrypting the introspection response
         * with an asymmetric algorithm.
         *
         * @return
         *         The public key for encrypting the introspection response
         *         with an asymmetric algorithm.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public String getPublicKeyForEncryption()
        {
            return publicKeyForEncryption;
        }


        /**
         * Set the public key for encrypting the introspection response with
         * an asymmetric algorithm.
         *
         * @param key
         *         The public key for encrypting the introspection response
         *         with an asymmetric algorithm.
         *
         * @return
         *         {@code this} object.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-jwt-introspection-response"
         *      >JWT Response for OAuth Token Introspection</a>
         */
        public Params setPublicKeyForEncryption(String key)
        {
            this.publicKeyForEncryption = key;

            return this;
        }
    }


    /**
     * Constructor with an implementation of {@link AuthleteApi} interface.
     *
     * @param api
     *         Implementation of {@link AuthleteApi} interface.
     */
    public IntrospectionRequestHandler(AuthleteApi api)
    {
        super(api);
    }


    /**
     * Handle an introspection request (<a href="https://tools.ietf.org/html/rfc7662"
     * >RFC 7662</a>).
     *
     * This method is an alias of the {@link #handle(Params)} method.
     *
     * @param parameters
     *         Request parameters of an introspection request.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the resource server.
     *
     * @throws WebApplicationException
     *         An error occurred.
     */
    public Response handle(MultivaluedMap<String, String> parameters) throws WebApplicationException
    {
        Params params = new Params()
                .setParameters(parameters)
                ;

        return handle(params);
    }


    /**
     * Handle an introspection request (<a href="https://tools.ietf.org/html/rfc7662"
     * >RFC 7662</a>).
     *
     * @param params
     *         Parameters needed to handle the introspection request.
     *         Must not be {@code null}.
     *
     * @return
     *         A response that should be returned from the endpoint to
     *         the resource server.
     *
     * @throws WebApplicationException
     *         An error occurred.
     *
     * @since 2.63
     */
    public Response handle(Params params) throws WebApplicationException
    {
        try
        {
            // Process the given parameters.
            return process(
                params.getParameters(),
                params.isWithHiddenProperties(),
                params.getHttpAcceptHeader(),
                params.getRsUri(),
                params.getIntrospectionSignAlg(),
                params.getIntrospectionEncryptionAlg(),
                params.getIntrospectionEncryptionEnc(),
                params.getSharedKeyForSign(),
                params.getSharedKeyForEncryption(),
                params.getPublicKeyForEncryption()
            );
        }
        catch (WebApplicationException e)
        {
            throw e;
        }
        catch (Throwable t)
        {
            // Unexpected error.
            throw unexpected("Unexpected error in IntrospectionRequestHandler", t);
        }
    }


    /**
     * Process the parameters of the introspection request.
     */
    private Response process(
            MultivaluedMap<String, String> parameters, boolean withHiddenProperties, String httpAcceptHeader,
            URI rsUri, JWSAlg introspectionSignAlg, JWEAlg introspectionEncAlg, JWEEnc introspectionEncEnc,
            String sharedKeyForSign, String sharedKeyForEncryption, String publicKeyForEncryption)
    {
        // Call Authlete's /api/auth/introspection/standard API.
        StandardIntrospectionResponse response = getApiCaller().callStandardIntrospection(
                parameters, withHiddenProperties, httpAcceptHeader, rsUri, introspectionSignAlg,
                introspectionEncAlg, introspectionEncEnc, sharedKeyForSign, sharedKeyForEncryption,
                publicKeyForEncryption);

        // 'action' in the response denotes the next action which
        // this service implementation should take.
        Action action = response.getAction();

        // The content of the response to the resource server.
        String content = response.getResponseContent();

        // Dispatch according to the action.
        switch (action)
        {
            case INTERNAL_SERVER_ERROR:
                // 500 Internal Server Error
                return ResponseUtil.internalServerError(content);

            case BAD_REQUEST:
                // 400 Bad Request
                return ResponseUtil.badRequest(content);

            case OK:
                // 200 OK
                return ResponseUtil.ok(content);

            case JWT:
                // 200 OK; application/token-introspection+jwt
                return ResponseUtil.tokenIntrospection(content);

            default:
                // This never happens.
                throw getApiCaller().unknownAction("/api/auth/introspection/standard", action);
        }
    }
}
