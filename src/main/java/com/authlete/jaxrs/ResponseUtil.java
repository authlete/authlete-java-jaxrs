/*
 * Copyright (C) 2015-2023 Authlete, Inc.
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


import java.util.Map;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;


/**
 * Utility class to generate a response from an endpoint.
 */
class ResponseUtil
{
    /**
     * {@code "application/json;charset=UTF-8"}
     */
    private static final MediaType MEDIA_TYPE_JSON =
            MediaType.APPLICATION_JSON_TYPE.withCharset("UTF-8");


    /**
     * {@code "text/html;charset=UTF-8"}
     */
    private static final MediaType MEDIA_TYPE_HTML =
            MediaType.TEXT_HTML_TYPE.withCharset("UTF-8");


    /**
     * {@code "application/jwt"}
     */
    static final MediaType MEDIA_TYPE_JWT = new MediaType("application", "jwt");


    /**
     * {@code "application/javascript;charset=UTF-8"}
     */
    private static final MediaType MEDIA_TYPE_JAVASCRIPT =
            new MediaType("application", "javascript", "UTF-8");


    /**
     * {@code "application/entity-statement+jwt"}
     */
    private static final MediaType MEDIA_TYPE_ENTITY_STATEMENT =
            new MediaType("application", "entity-statement+jwt");


    /**
     * {@code "application/token-introspection+jwt"}
     */
    private static final MediaType MEDIA_TYPE_TOKEN_INTROSPECTION =
            new MediaType("application", "token-introspection+jwt");


    /**
     * {@code "application/jose"}
     */
    private static final MediaType MEDIA_TYPE_JOSE =
            new MediaType("application", "jose");


    /**
     * {@code "Cache-Control: no-store"}
     */
    private static final CacheControl CACHE_CONTROL;


    static
    {
        // Setup for Cache-Control header.
        CACHE_CONTROL = new CacheControl();
        CACHE_CONTROL.setNoStore(true);
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response ok(String entity)
    {
        return ok(entity, /* headers */ (Map<String, Object>)null);
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     *
     * @since 2.66
     */
    public static Response ok(
            String entity, Map<String, Object> headers)
    {
        return ok(entity, MEDIA_TYPE_JSON, headers);
    }


    /**
     * Create a response of {@code "200 OK"} with the given entity
     * with the given media format.
     */
    public static Response ok(String entity, MediaType mediaType)
    {
        return ok(entity, mediaType, /* headers */ null);
    }


    /**
     * Create a response of {@code "200 OK"} with the given entity
     * with the given media format.
     *
     * @since 2.66
     */
    public static Response ok(
            String entity, MediaType mediaType, Map<String, Object> headers)
    {
        return builder(Status.OK, entity, mediaType, headers).build();
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "text/html;charset=UTF-8"}.
     */
    public static Response form(String entity)
    {
        return builder(Status.OK, entity, MEDIA_TYPE_HTML).build();
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "application/javascript;charset=UTF-8"}.
     */
    public static Response javaScript(String entity)
    {
        return builder(Status.OK, entity, MEDIA_TYPE_JAVASCRIPT).build();
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "application/entity-statement+jwt"}.
     */
    public static Response entityStatement(String entity)
    {
        return builder(Status.OK, entity, MEDIA_TYPE_ENTITY_STATEMENT).build();
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "application/token-introspection+jwt"}.
     */
    public static Response tokenIntrospection(String entity)
    {
        return builder(Status.OK, entity, MEDIA_TYPE_TOKEN_INTROSPECTION).build();
    }


    /**
     * Create a response of {@code "200 OK"}
     * with the given entity formatted in
     * {@code "application/jose"}.
     */
    public static Response jose(String entity)
    {
        return builder(Status.OK, entity, MEDIA_TYPE_JOSE).build();
    }


    /**
     * Create a response of {@code "204 No Content"}.
     */
    public static Response noContent()
    {
        return noContent(/* headers */ null);
    }


    /**
     * Create a response of {@code "204 No Content"}.
     *
     * @since 2.66
     */
    public static Response noContent(Map<String, Object> headers)
    {
        return builder(Status.NO_CONTENT, headers).build();
    }


    /**
     * Create a response of {@code "302 Found"}
     * with {@code Location} header having the given location.
     */
    public static Response location(String location)
    {
        return builder(Status.FOUND)
                .header(HttpHeaders.LOCATION, location)
                .build();
    }


    /**
     * Create a response of {@code "400 Bad Request"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response badRequest(String entity)
    {
        return badRequest(entity, /* headers */ null);
    }


    /**
     * Create a response of {@code "400 Bad Request"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     *
     * @since 2.66
     */
    public static Response badRequest(
            String entity, Map<String, Object> headers)
    {
        return builder(Status.BAD_REQUEST, entity, MEDIA_TYPE_JSON, headers).build();
    }


    /**
     * Create a response of {@code "401 Unauthorized"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"} and
     * with {@code WWW-Authenticate} header having the
     * value specified by {@code challenge}.
     */
    public static Response unauthorized(String entity, String challenge)
    {
        return unauthorized(entity, challenge, /* headers */ null);
    }


    /**
     * Create a response of {@code "401 Unauthorized"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"} and
     * with {@code WWW-Authenticate} header having the
     * value specified by {@code challenge}.
     *
     * @since 2.66
     */
    public static Response unauthorized(
            String entity, String challenge, Map<String, Object> headers)
    {
        ResponseBuilder builder =
                builder(Status.UNAUTHORIZED, entity, MEDIA_TYPE_JSON, headers);

        if (challenge != null)
        {
            builder.header(HttpHeaders.WWW_AUTHENTICATE, challenge);
        }

        return builder.build();
    }


    /**
     * Create a response of {@code "403 Forbidden"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response forbidden(String entity)
    {
        return forbidden(entity, /* headers */ null);
    }


    /**
     * Create a response of {@code "403 Forbidden"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     *
     * @since 2.66
     */
    public static Response forbidden(
            String entity, Map<String, Object> headers)
    {
        return builder(Status.FORBIDDEN, entity, MEDIA_TYPE_JSON, headers).build();
    }


    /**
     * Create a response of {@code "404 Not Found"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response notFound(String entity)
    {
        return notFound(entity, /* headers */ null);
    }


    /**
     * Create a response of {@code "404 Not Found"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     *
     * @since 2.66
     */
    public static Response notFound(
            String entity, Map<String, Object> headers)
    {
        return builder(Status.NOT_FOUND, entity, MEDIA_TYPE_JSON, headers).build();
    }


    /**
     * Create a response of {@code "500 Internal Server Error"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response internalServerError(String entity)
    {
        return internalServerError(entity, /* header */ (Map<String, Object>)null);
    }


    /**
     * Create a response of {@code "500 Internal Server Error"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     *
     * @since 2.66
     */
    public static Response internalServerError(
            String entity, Map<String, Object> headers)
    {
        return internalServerError(entity, MEDIA_TYPE_JSON, headers);
    }


    /**
     * Create a response of {@code "201 Created"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response created(String entity)
    {
        return created(entity, /* headers */ null);
    }


    /**
     * Create a response of {@code "201 Created"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     *
     * @since 2.66
     */
    public static Response created(
            String entity, Map<String, Object> headers)
    {
        return builder(Status.CREATED, entity, MEDIA_TYPE_JSON, headers).build();
    }


    /**
     * Create a response of {@code "500 Internal Server Error"}
     * with the given entity.
     */
    public static Response internalServerError(String entity, MediaType mediaType)
    {
        return internalServerError(entity, mediaType, /* headers */ null);
    }


    /**
     * Create a response of {@code "500 Internal Server Error"}
     * with the given entity.
     *
     * @since 2.66
     */
    public static Response internalServerError(
            String entity, MediaType mediaType, Map<String, Object> headers)
    {
        return builder(Status.INTERNAL_SERVER_ERROR, entity, mediaType, headers).build();
    }


    /**
     * Create a {@link ResponseBuilder} with the specified status,
     * {@code Cache-Control} header and {@code Pragma} header.
     */
    private static ResponseBuilder builder(Status status)
    {
        return builder(status, /* headers */ null);
    }


    private static ResponseBuilder builder(
            Status status, Map<String, Object> headers)
    {
        ResponseBuilder builder = Response
                .status(status)
                .cacheControl(CACHE_CONTROL)
                .header("Pragma", "no-cache");

        // If additional headers are given.
        if (headers != null)
        {
            // For each additional header.
            for (Map.Entry<String, Object> header : headers.entrySet())
            {
                // Add the header to the builder.
                builder.header(header.getKey(), header.getValue());
            }
        }

        return builder;
    }


    /**
     * Create a {@link ResponseBuilder}.
     */
    private static ResponseBuilder builder(Status status, String entity, MediaType type)
    {
        return builder(status, entity, type, /* headers */ null);
    }


    private static ResponseBuilder builder(
            Status status, String entity, MediaType type, Map<String, Object> headers)
    {
        return builder(status, headers).entity(entity).type(type);
    }


    /**
     * Create a response with the given status and {@code WWW-Authenticate}
     * header having the given challenge as its value.
     */
    public static Response bearerError(Status status, String challenge)
    {
        return bearerError(status, challenge, /* headers */ null);
    }


    /**
     * Create a response with the given status and {@code WWW-Authenticate}
     * header having the given challenge as its value.
     *
     * @since 2.66
     */
    public static Response bearerError(
            Status status, String challenge, Map<String, Object> headers)
    {
        return builder(status, headers).header("WWW-Authenticate", challenge).build();
    }


    /**
     * Create a response of {@code 413 Request Entity Too Large} with
     * the given entity.
     *
     * @since 2.21
     */
    public static Response tooLarge(String entity)
    {
        return tooLarge(entity, /* headers */ null);
    }


    /**
     * Create a response of {@code 413 Request Entity Too Large} with
     * the given entity.
     *
     * @since 2.66
     */
    public static Response tooLarge(
            String entity, Map<String, Object> headers)
    {
        return builder(Status.REQUEST_ENTITY_TOO_LARGE, entity, MEDIA_TYPE_JSON, headers).build();
    }
}
