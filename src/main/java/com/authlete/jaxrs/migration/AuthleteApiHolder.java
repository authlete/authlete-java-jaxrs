package com.authlete.jaxrs.migration;

import com.authlete.common.api.AuthleteApi;
import com.authlete.common.api.AuthleteApiFactory;
import com.authlete.common.conf.AuthleteApiVersion;
import com.authlete.common.conf.AuthleteConfiguration;
import com.authlete.common.conf.AuthletePropertiesConfiguration;
import com.authlete.common.conf.AuthleteSimpleConfiguration;
import com.authlete.common.util.PropertiesLoader;
import com.authlete.common.util.TypedProperties;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * @author kylegonzalez
 */
public class AuthleteApiHolder
{
    private static final String BASE_URL_SECONDARY = "base_url.secondary";
    private static final Gson gson = new Gson();
    private static final Type type = new TypeToken<Map<String, Object>>() {}.getType();
    private static AuthleteApiHolder INSTANCE = null;

    private final Logger logger = LoggerFactory.getLogger(getClass());

    /**
     * The secondary Authlete API, if both are configured, this should be connected to the Authlete 2.3 server.
     */
    private final AuthleteApi secondaryAuthleteApi;

    /**
     * The primary Authlete Api, if both are configured, this should be connected to the Authlete 3 server.
     */
    private final AuthleteApi primaryAuthleteApi;

    private AuthleteApiHolder()
    {
        AuthleteConfiguration initialConfiguration = new AuthletePropertiesConfiguration();
        primaryAuthleteApi = AuthleteApiFactory.create(initialConfiguration);
        logger.info("Initializing configuration for Authlete Api with version [{}]", initialConfiguration.getApiVersion());

        // If V3 is specified and the base secondary endpoint is also provided we should initialise a secondary api
        // this assumes the secondary is always version 2
        String secondaryBaseUrl = getSecondaryBaseUrl();
        if (AuthleteApiVersion.V3.name().equalsIgnoreCase(initialConfiguration.getApiVersion()) && secondaryBaseUrl != null)
        {
            logger.info("Api Version set to [{}] but the [{}] property value has also been provided. Initializing migration support mode using the provided Authlete 2.3 (secondary) [{}] and Authlete 3 (primary) [{}] endpoints.",
                    initialConfiguration.getApiVersion(), BASE_URL_SECONDARY, secondaryBaseUrl, initialConfiguration.getBaseUrl());

            AuthleteConfiguration v2Configuration = new AuthleteSimpleConfiguration()
                    .setBaseUrl(secondaryBaseUrl)
                    .setApiVersion(AuthleteApiVersion.V2.name())
                    .setServiceApiSecret(initialConfiguration.getServiceApiSecret())
                    .setServiceApiKey(initialConfiguration.getServiceApiKey())
                    .setServiceOwnerApiKey(initialConfiguration.getServiceOwnerApiKey())
                    .setServiceOwnerApiSecret(initialConfiguration.getServiceOwnerApiSecret())
                    .setDpopKey(initialConfiguration.getDpopKey())
                    .setClientCertificate(initialConfiguration.getClientCertificate());

            secondaryAuthleteApi = AuthleteApiFactory.create(v2Configuration);
        }
        else
        {
            secondaryAuthleteApi = null;
        }
    }

    /**
     * Taken from {@link AuthletePropertiesConfiguration}
     * @return the configured properties file name
     */
    private static String getFile()
    {
        String file = System.getProperty("authlete.configuration.file");
        return file != null && !file.isEmpty() ? file : "authlete.properties";
    }

    private String getSecondaryBaseUrl()
    {
        String propertiesFile = getFile();
        TypedProperties props = PropertiesLoader.load(propertiesFile);

        if (props == null)
        {
            return null;
        }

        return props.getString(BASE_URL_SECONDARY);
    }

    public static AuthleteApiHolder getInstance()
    {
        if (INSTANCE != null)
        {
            return INSTANCE;
        }

        synchronized (AuthleteApiHolder.class)
        {
            if (INSTANCE != null)
            {
                return INSTANCE;
            }
            INSTANCE = new AuthleteApiHolder();
        }

        return INSTANCE;
    }

    public Response withApi(Function<AuthleteApi, Response> function, TriFunction<Response, Map<String, Object>, Throwable, Boolean> isErrorFunction)
    {
        return withApi(CallerStrategy.UNTIL_SUCCESS, ResponseReturnStrategy.FIRST_NON_ERROR_RESPONSE, function, isErrorFunction);
    }

    public Response withApi(Function<AuthleteApi, Response> function)
    {
        return withApi(ResponseReturnStrategy.FIRST_NON_ERROR_RESPONSE, function);
    }

    public Response withApi(ResponseReturnStrategy strategy, Function<AuthleteApi, Response> function)
    {
        return withApi(CallerStrategy.UNTIL_SUCCESS, strategy, function);
    }

    public Response withApi(CallerStrategy callerStrategy, ResponseReturnStrategy strategy, Function<AuthleteApi, Response> function)
    {
        return withApi(callerStrategy, strategy, function,
                // Default error function filters out by HTTP error response code
                (res, body, throwable) -> throwable != null || res.getStatus() >= Response.Status.BAD_REQUEST.getStatusCode());
    }

    public Response withApi(CallerStrategy callerStrategy, ResponseReturnStrategy strategy, Function<AuthleteApi, Response> function, TriFunction<Response, Map<String, Object>, Throwable, Boolean> isErrorFunction)
    {
        Response primaryResponse = null;
        Throwable throwable = null;
        try
        {
            primaryResponse = function.apply(primaryAuthleteApi);
        }
        catch (Throwable t)
        {
            if (t instanceof WebApplicationException)
            {
                primaryResponse = ((WebApplicationException) t).getResponse();
            }

            throwable = t;
        }

        boolean primaryIsError = primaryResponse == null
                || isErrorFunction.apply(primaryResponse, getResponseAsMap(primaryResponse), throwable);
        if (secondaryAuthleteApi == null
            || callerStrategy == CallerStrategy.ONLY_PRIMARY
            || (callerStrategy == CallerStrategy.UNTIL_SUCCESS && !primaryIsError))
        {
            return primaryResponse;
        }

        Response secondaryResponse = null;
        throwable = null;
        try
        {
            secondaryResponse = function.apply(secondaryAuthleteApi);
        }
        catch (Throwable t)
        {
            if (t instanceof WebApplicationException)
            {
                secondaryResponse = ((WebApplicationException) t).getResponse();
            }

            throwable = t;
        }
        boolean secondaryIsError = secondaryResponse == null
                || isErrorFunction.apply(secondaryResponse, getResponseAsMap(secondaryResponse), throwable);

        // We won't check for ResponseReturnStrategy.PRIMARY since returning the primary response is the default
        // fall through case

        if (strategy == ResponseReturnStrategy.SECONDARY)
        {
            return secondaryResponse;
        }
        else if (strategy == ResponseReturnStrategy.FIRST_NON_ERROR_RESPONSE)
        {
            if (!primaryIsError)
            {
                return primaryResponse;
            }
            else if (!secondaryIsError)
            {
                return secondaryResponse;
            }
        }
        else if (strategy == ResponseReturnStrategy.LAST_NON_ERROR_RESPONSE)
        {
            if (!secondaryIsError)
            {
                return secondaryResponse;
            }
            else if (!primaryIsError)
            {
                return primaryResponse;
            }
        }
        else if (strategy == ResponseReturnStrategy.BOTH_ERROR_THEN_SECONDARY)
        {
            if (primaryIsError && secondaryIsError)
            {
                return secondaryResponse;
            }
        }
        else if (strategy == ResponseReturnStrategy.BOTH_ERROR_THEN_PRIMARY)
        {
            if (primaryIsError && secondaryIsError)
            {
                return primaryResponse;
            }
        }
        else if (strategy == ResponseReturnStrategy.ONE_ERROR_THAN_ERROR)
        {
            if (primaryIsError && !secondaryIsError)
            {
                return primaryResponse;
            }
            else if (!primaryIsError && secondaryIsError)
            {
                return secondaryResponse;
            }
        }
        else if (strategy == ResponseReturnStrategy.ONE_ERROR_THAN_SUCCESS)
        {
            if (primaryIsError && !secondaryIsError)
            {
                return secondaryResponse;
            }
            else if (!primaryIsError && secondaryIsError)
            {
                return primaryResponse;
            }
        }

        // Always return primary response by default
        return primaryResponse;
    }

    private static Map<String, Object> getResponseAsMap(Response response)
    {
        if (response == null)
        {
            return new HashMap<>();
        }

        response.bufferEntity();
        try
        {
            String json = response.getEntity().toString();
            return gson.fromJson(json, type);
        }
        catch (Throwable t)
        {
            // If we fail to parse its probably a html response not json so fall through and return an empty map
        }
        return new HashMap<>();
    }
}
