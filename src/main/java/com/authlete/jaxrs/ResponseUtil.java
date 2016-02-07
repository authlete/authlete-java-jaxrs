/*
 * Copyright (C) 2015-2016 Authlete, Inc.
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


import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;


/**
 * Utility class to generate a response from an endpoint.
 *
 * @author Takahiko Kawasaki
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
        return ok(entity, MEDIA_TYPE_JSON);
    }


    /**
     * Create a response of {@code "200 OK"} with the given entity
     * with the given media format.
     */
    public static Response ok(String entity, MediaType mediaType)
    {
        return builder(Status.OK, entity, mediaType).build();
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
     * Create a response of {@code "204 No Content"}.
     */
    public static Response noContent()
    {
        return builder(Status.NO_CONTENT).build();
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
        return builder(Status.BAD_REQUEST, entity, MEDIA_TYPE_JSON).build();
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
        return builder(Status.UNAUTHORIZED, entity, MEDIA_TYPE_JSON)
                .header(HttpHeaders.WWW_AUTHENTICATE, challenge)
                .build();
    }


    /**
     * Create a response of {@code "403 Forbidden"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response forbidden(String entity)
    {
        return builder(Status.FORBIDDEN, entity, MEDIA_TYPE_JSON).build();
    }


    /**
     * Create a response of {@code "404 Not Found"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response notFound(String entity)
    {
        return builder(Status.NOT_FOUND, entity, MEDIA_TYPE_JSON).build();
    }


    /**
     * Create a response of {@code "500 Internal Server Error"}
     * with the given entity formatted in
     * {@code "application/json;charset=UTF-8"}.
     */
    public static Response internalServerError(String entity)
    {
        return internalServerError(entity, MEDIA_TYPE_JSON);
    }


    /**
     * Create a response of {@code "500 Internal Server Error"}
     * with the given entity.
     */
    public static Response internalServerError(String entity, MediaType mediaType)
    {
        return builder(Status.INTERNAL_SERVER_ERROR, entity, mediaType).build();
    }


    /**
     * Create a {@link ResponseBuilder} with the specified status,
     * {@code Cache-Control} header and {@code Pragma} header.
     */
    private static ResponseBuilder builder(Status status)
    {
        return Response
                .status(status)
                .cacheControl(CACHE_CONTROL)
                .header("Pragma", "no-cache");
    }


    /**
     * Create a {@link ResponseBuilder}.
     */
    private static ResponseBuilder builder(Status status, String entity, MediaType type)
    {
        return builder(status)
                .entity(entity)
                .type(type);
    }


    /**
     * Create a response with the given status and {@code WWW-Authenticate}
     * header having the given challenge as its value.
     */
    public static Response bearerError(Status status, String challenge)
    {
        return builder(status).header("WWW-Authenticate", challenge).build();
    }
}
