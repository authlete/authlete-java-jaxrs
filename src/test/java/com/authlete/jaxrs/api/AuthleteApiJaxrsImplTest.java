package com.authlete.jaxrs.api;


import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiException;
import com.authlete.common.api.Options;
import com.authlete.common.conf.AuthleteConfiguration;
import com.authlete.common.dto.AuthorizationRequest;
import com.authlete.common.dto.AuthorizationResponse;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


/**
 * Tests for {@link AuthleteApiJaxrsImpl} to verify that non-2xx HTTP
 * responses from the Authlete API are correctly raised as
 * {@link AuthleteApiException} with the appropriate status code.
 *
 * <p>
 * The JAX-RS typed overloads ({@code builder.get(Class)},
 * {@code builder.post(Entity, Class)}) throw
 * {@code WebApplicationException} on non-2xx responses, whereas the
 * untyped overloads ({@code builder.get()}, {@code builder.post(Entity)})
 * return the {@code Response} silently. These tests ensure that the
 * explicit status check is in place so that the error-handling contract
 * is preserved regardless of which overload is used internally.
 * </p>
 */
public class AuthleteApiJaxrsImplTest
{
    private static class TestHarness
    {
        final Invocation.Builder builder;
        final AuthleteApi api;

        TestHarness()
        {
            AuthleteConfiguration configuration =
                    mock(AuthleteConfiguration.class);
            when(configuration.getBaseUrl()).thenReturn("http://example.com");
            when(configuration.getServiceApiKey()).thenReturn("key");
            when(configuration.getServiceApiSecret()).thenReturn("secret");
            when(configuration.getApiVersion()).thenReturn("V2");

            Client client = mock(Client.class);
            WebTarget webTarget = mock(WebTarget.class);
            builder = mock(Invocation.Builder.class);

            ClientBuilder clientBuilder = mock(ClientBuilder.class);
            doReturn(client).when(clientBuilder).build();
            doReturn(webTarget).when(client).target(anyString());
            doReturn(webTarget).when(webTarget).path(anyString());
            doReturn(webTarget).when(webTarget)
                    .queryParam(anyString(), any());
            doReturn(builder).when(webTarget).request();
            doReturn(builder).when(webTarget)
                    .request(any(MediaType.class));
            doReturn(builder).when(builder).header(anyString(), any());

            AuthleteApiImpl impl = new AuthleteApiImpl(configuration);
            impl.setJaxRsClientBuilder(clientBuilder);
            api = impl;
        }
    }


    private static Response createErrorResponse(int statusCode)
    {
        Response response = mock(Response.class);
        Response.StatusType statusType = mock(Response.StatusType.class);

        doReturn(statusCode).when(statusType).getStatusCode();
        doReturn("Error").when(statusType).getReasonPhrase();
        doReturn(Response.Status.Family.familyOf(statusCode))
                .when(statusType).getFamily();

        doReturn(statusType).when(response).getStatusInfo();
        doReturn(statusCode).when(response).getStatus();
        doReturn(true).when(response).hasEntity();
        doReturn("{\"resultCode\":\"error\"}")
                .when(response).readEntity(String.class);
        doReturn(new MultivaluedHashMap<String, String>())
                .when(response).getStringHeaders();

        return response;
    }


    private static Response createSuccessResponse()
    {
        Response response = mock(Response.class);
        Response.StatusType statusType = mock(Response.StatusType.class);

        doReturn(Response.Status.Family.SUCCESSFUL)
                .when(statusType).getFamily();
        doReturn(statusType).when(response).getStatusInfo();
        doReturn(new MultivaluedHashMap<String, String>())
                .when(response).getStringHeaders();

        return response;
    }


    // ---------------------------------------------------------------
    // POST: non-2xx should throw AuthleteApiException
    // ---------------------------------------------------------------

    @Test
    public void testPostApiThrowsOn400()
    {
        TestHarness h = new TestHarness();
        Response response = createErrorResponse(400);
        doReturn(response).when(h.builder).post(any());

        AuthleteApiException ex = assertThrows(
                AuthleteApiException.class,
                () -> h.api.authorization(
                        new AuthorizationRequest(), new Options()));

        assertEquals(400, ex.getStatusCode());
    }

    @Test
    public void testPostApiThrowsOn401()
    {
        TestHarness h = new TestHarness();
        Response response = createErrorResponse(401);
        doReturn(response).when(h.builder).post(any());

        AuthleteApiException ex = assertThrows(
                AuthleteApiException.class,
                () -> h.api.authorization(
                        new AuthorizationRequest(), new Options()));

        assertEquals(401, ex.getStatusCode());
    }

    @Test
    public void testPostApiThrowsOn500()
    {
        TestHarness h = new TestHarness();
        Response response = createErrorResponse(500);
        doReturn(response).when(h.builder).post(any());

        AuthleteApiException ex = assertThrows(
                AuthleteApiException.class,
                () -> h.api.authorization(
                        new AuthorizationRequest(), new Options()));

        assertEquals(500, ex.getStatusCode());
    }


    // ---------------------------------------------------------------
    // GET: non-2xx should throw AuthleteApiException
    // ---------------------------------------------------------------

    @Test
    public void testGetApiThrowsOn400()
    {
        TestHarness h = new TestHarness();
        Response response = createErrorResponse(400);
        doReturn(response).when(h.builder).get();

        AuthleteApiException ex = assertThrows(
                AuthleteApiException.class,
                () -> h.api.getServiceJwks(new Options()));

        assertEquals(400, ex.getStatusCode());
    }

    @Test
    public void testGetApiThrowsOn401()
    {
        TestHarness h = new TestHarness();
        Response response = createErrorResponse(401);
        doReturn(response).when(h.builder).get();

        AuthleteApiException ex = assertThrows(
                AuthleteApiException.class,
                () -> h.api.getServiceJwks(new Options()));

        assertEquals(401, ex.getStatusCode());
    }

    @Test
    public void testGetApiThrowsOn500()
    {
        TestHarness h = new TestHarness();
        Response response = createErrorResponse(500);
        doReturn(response).when(h.builder).get();

        AuthleteApiException ex = assertThrows(
                AuthleteApiException.class,
                () -> h.api.getServiceJwks(new Options()));

        assertEquals(500, ex.getStatusCode());
    }


    // ---------------------------------------------------------------
    // 2xx success paths
    // ---------------------------------------------------------------

    @Test
    public void testPostApiSucceedsOn200()
    {
        TestHarness h = new TestHarness();
        Response response = createSuccessResponse();
        doReturn(new AuthorizationResponse())
                .when(response).readEntity(AuthorizationResponse.class);
        doReturn(response).when(h.builder).post(any());

        AuthorizationResponse result = h.api.authorization(
                new AuthorizationRequest(), new Options());

        assertNotNull(result);
    }

    @Test
    public void testGetApiSucceedsOn200()
    {
        TestHarness h = new TestHarness();
        Response response = createSuccessResponse();
        doReturn("{\"keys\":[]}").when(response).readEntity(String.class);
        doReturn(response).when(h.builder).get();

        String result = h.api.getServiceJwks(new Options());

        assertNotNull(result);
    }

    @Test
    public void testDeleteApiSucceeds()
    {
        TestHarness h = new TestHarness();
        Response response = mock(Response.class);
        doReturn(200).when(response).getStatus();
        doReturn(response).when(h.builder).delete();

        h.api.deleteClient("123", new Options());
    }

    // ---------------------------------------------------------------
    // Serialization
    // ---------------------------------------------------------------
    @Test
    @SuppressWarnings("unchecked")
    public void testResponseHeadersAreSerializableAfterWrappingInHashMap()
    {
        TestHarness h = new TestHarness();

        // Mockito mocks do not implement Serializable, mirroring the behaviour of
        // CXF's MetadataMap. Without the HashMap-wrapping fix, serialization would fail.
        MultivaluedMap<String, String> nonSerializableHeaders = mock(MultivaluedMap.class);

        Response mockResponse = createSuccessResponse();
        doReturn(nonSerializableHeaders).when(mockResponse).getStringHeaders();
        doReturn(new AuthorizationResponse()).when(mockResponse).readEntity(AuthorizationResponse.class);
        doReturn(mockResponse).when(h.builder).post(any());

        AuthorizationResponse result = ((AuthleteApiJaxrsImpl) h.api).callPostApi(
                "Bearer test",
                "/api/auth/authorization",
                new AuthorizationRequest(),
                AuthorizationResponse.class,
                new Options());

        assertDoesNotThrow(() -> {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new ObjectOutputStream(baos).writeObject(result);
        });
    }
}
