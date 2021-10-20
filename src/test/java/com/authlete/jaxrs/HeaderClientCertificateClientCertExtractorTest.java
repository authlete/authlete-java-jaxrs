package com.authlete.jaxrs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.greenbytes.http.sfv.ParseException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class HeaderClientCertificateClientCertExtractorTest {

  public static final String CLIENT_CERT = "Client-Cert";
  public static final String CLIENT_CERT_VALUE = ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:";
  public static final String CLIENT_CERT_CHAIN = "Client-Cert-Chain";
  public static final String CLIENT_CERT_CHAIN_VALUE = ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:,:cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:,:cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:";
  public static final String CLIENT_CERT_WRONG_VALUE = ":wrong value:";
  public static final String CLIENT_CERT_ENCODED = "pretend this is binary content.";
  private HeaderClientCertificateClientCertExtractor headerClientCertificateClientCertExtractorUnderTest;

  @BeforeEach
  void setUp()
  {
    headerClientCertificateClientCertExtractorUnderTest = new HeaderClientCertificateClientCertExtractor();
  }

  @Test
  @DisplayName("Extract Client-Cert and Client-Cert-Chain")
  void should_extract_ClientCert_and_ClientCertChain()
  {
    HttpServletRequest mockHttpServletRequest = getMockHttpServletRequest(CLIENT_CERT_VALUE,CLIENT_CERT_CHAIN_VALUE);

    // Run the test
    final String[] result = headerClientCertificateClientCertExtractorUnderTest
        .extractClientCertificateChain(mockHttpServletRequest);

    // Verify the results
    String[] expected = new String[4];
    for (int i = 0; i < 4; i++) {
      expected[i] = CLIENT_CERT_ENCODED;
    }
    assertEquals(result.length, 4);
    assertArrayEquals(expected, result);
  }

  @Test
  @DisplayName("Fail Extract Client-Cert and Client-Cert-Chain due to headers are null")
  void should_fail_extract_Certs_due_to_headers_value_are_null()
  {

// mock HttpServletRequest
    final HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

    when(mockHttpServletRequest.getHeader(CLIENT_CERT)).thenReturn(null);
    when(mockHttpServletRequest.getHeader(CLIENT_CERT_CHAIN))
        .thenReturn(null);

    // Verify the results
    assertThrows(NullPointerException.class, new Executable() {
      @Override
      public void execute() {
        headerClientCertificateClientCertExtractorUnderTest
            .extractClientCertificateChain(mockHttpServletRequest);
      }
    });
  }

  @Test
  @DisplayName("Should return null due to headers are null")
  void should_return_null_due_to_headers_are_null()
  {

// mock HttpServletRequest
    final HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);

    /// Run the test
    final String[] result = headerClientCertificateClientCertExtractorUnderTest
        .extractClientCertificateChain(mockHttpServletRequest);

    // Verify the results
    assertEquals(result,null);
  }

  @Test
  @DisplayName("Fail Extract Client-Cert and Client-Cert-Chain due to Parsing Error")
  void should_fail_extract_Certs_due_to_parse_Cert()
  {

    final HttpServletRequest mockHttpServletRequest = getMockHttpServletRequest(CLIENT_CERT_WRONG_VALUE,CLIENT_CERT_WRONG_VALUE);

    // Verify the results
    assertThrows(ParseException.class, new Executable() {
      @Override
      public void execute() {
        headerClientCertificateClientCertExtractorUnderTest
            .extractClientCertificateChain(mockHttpServletRequest);
      }
    });
  }

  private HttpServletRequest getMockHttpServletRequest(String certVal,String certChainVal) {
    // Setup Http servlet request with Client-Cert header
    // define the Client-Cert header that we want to be returned
    Map<String, String> headers = new HashMap<>();
    headers.put(CLIENT_CERT,
        certVal);
    headers.put(CLIENT_CERT_CHAIN,
        certChainVal);

// create an Enumeration over the header key
    Enumeration<String> headerNames = Collections.enumeration(headers.keySet());

// mock HttpServletRequest
    HttpServletRequest mockHttpServletRequest = mock(HttpServletRequest.class);
// mock the returned value of request.getHeaderNames()
    when(mockHttpServletRequest.getHeaderNames()).thenReturn(headerNames);
    when(mockHttpServletRequest.getHeader(CLIENT_CERT)).thenReturn(headers.get(CLIENT_CERT));
    when(mockHttpServletRequest.getHeader(CLIENT_CERT_CHAIN))
        .thenReturn(headers.get(CLIENT_CERT_CHAIN));
    return mockHttpServletRequest;
  }
}
