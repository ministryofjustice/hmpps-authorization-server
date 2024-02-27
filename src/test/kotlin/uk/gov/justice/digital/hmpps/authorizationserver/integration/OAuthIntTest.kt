package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.assertj.core.api.Assertions.assertThat
import org.hamcrest.CoreMatchers.allOf
import org.hamcrest.CoreMatchers.containsString
import org.hamcrest.CoreMatchers.startsWith
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters.fromFormData
import uk.gov.justice.digital.hmpps.authorizationserver.service.AuthSource
import uk.gov.justice.digital.hmpps.authorizationserver.service.JWKKeyAccessor
import java.time.Duration
import java.util.Base64
import java.util.Date

class OAuthIntTest : IntegrationTestBase() {

  @Autowired
  private lateinit var jwkKeyAccessor: JWKKeyAccessor

  @MockBean
  private lateinit var telemetryClient: TelemetryClient

  @Nested
  inner class ClientCredentials {

    @Test
    fun `client with database username`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()))
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(301)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("test-client-id")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("authorities")).isEqualTo(JSONArray(listOf("ROLE_AUDIT", "ROLE_OAUTH_ADMIN", "ROLE_TESTING")))

      assertThat(token.get("database_username")).isEqualTo("testy-db")
      assertTrue(token.isNull("user_name"))
    }

    @Test
    fun `client without database username`() {
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("ip-allow-a-client-1:test-secret").toByteArray()))
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .jsonPath("$").value<Map<String, Any>> {
          assertThat(it["expires_in"] as Int).isLessThan(301)
        }
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("ip-allow-a-client-1")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")

      assertTrue(token.isNull("database_username"))
      assertTrue(token.isNull("user_name"))
    }

    @Test
    fun `user name passed in`() {
      val map = LinkedMultiValueMap<String, String>()
      map.add("grant_type", "client_credentials")
      map.add("username", "testy")
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData(map),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("testy")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertThat(token.get("authorities")).isEqualTo(JSONArray(listOf("ROLE_AUDIT", "ROLE_OAUTH_ADMIN", "ROLE_TESTING")))

      assertThat(token.get("database_username")).isEqualTo("testy-db")
      assertThat(token.get("user_name")).isEqualTo("testy")
    }

    @Test
    fun `auth source passed in`() {
      val map = LinkedMultiValueMap<String, String>()
      map.add("grant_type", "client_credentials")
      map.add("auth_source", "delius")
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData(map),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse!!))
      assertThat(token.get("sub")).isEqualTo("test-client-create-id")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("delius")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertTrue(token.isNull("authorities"))

      assertTrue(token.isNull("user_name"))
      assertTrue(token.isNull("database_username"))
    }

    @Test
    fun `unrecognised auth source passed in`() {
      val map = LinkedMultiValueMap<String, String>()
      map.add("grant_type", "client_credentials")
      map.add("auth_source", "xdelius")
      val clientCredentialsResponse = webTestClient
        .post().uri("/oauth2/token")
        .header(
          HttpHeaders.AUTHORIZATION,
          "Basic " + Base64.getEncoder().encodeToString(("test-client-create-id:test-secret").toByteArray()),
        )
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData(map),
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(clientCredentialsResponse))
      assertThat(token.get("sub")).isEqualTo("test-client-create-id")
      assertThat(token.get("aud")).isEqualTo("oauth2-resource")
      assertThat(token.get("auth_source")).isEqualTo("none")
      assertThat(token.get("grant_type")).isEqualTo("client_credentials")
      assertTrue(token.isNull("authorities"))

      assertTrue(token.isNull("user_name"))
      assertTrue(token.isNull("database_username"))
    }

    @Test
    fun `incorrect secret`() {
      webTestClient
        .post().uri("/oauth2/token")
        .header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(("test-client-id:test-secretx").toByteArray()))
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationServerCreateAccessTokenFailure",
        mapOf("clientId" to "test-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }

    @Test
    fun `unrecognised client id`() {
      webTestClient
        .post().uri("/oauth2/token")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("unrecognised-client-id:test-secret").toByteArray()))
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized

      verify(telemetryClient).trackEvent(
        "AuthorizationServerCreateAccessTokenFailure",
        mapOf("clientId" to "unrecognised-client-id", "clientIpAddress" to "127.0.0.1"),
        null,
      )
    }

    @Test
    fun `anonymous token request`() {
      webTestClient
        .post().uri("/oauth2/token")
        .contentType(APPLICATION_FORM_URLENCODED)
        .body(
          fromFormData("grant_type", "client_credentials"),
        )
        .exchange()
        .expectStatus().isUnauthorized
    }
  }

  @Nested
  inner class AuthorizationCode {

    private val validRedirectUri = "http://127.0.0.1:8089/login/oauth2/code/oidc-client"
    private val invalidRedirectUri = "http://127.0.0.1:8089/login/oauth2/code/oidc-client-x"
    private val validClientId = "test-auth-code-client"
    private val invalidClientId = "test-auth-code-client-x"
    private val state = "1234"

    @Test
    fun `unauthenticated user`() {
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .exchange()
        .expectStatus().isUnauthorized
    }

    @Test
    fun `invalid client id`() {
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=$invalidClientId&state=$state&redirect_uri=$validRedirectUri")
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isBadRequest
    }

    @Test
    fun `invalid redirect url`() {
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$invalidRedirectUri")
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isBadRequest
    }

    @Test
    fun `missing response type`() {
      webTestClient
        .get().uri("/oauth2/authorize?client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isBadRequest
    }

    @Test
    fun `success redirects with code`() {
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectStatus().isFound
        .expectHeader()
        .value("Location", allOf(startsWith(validRedirectUri), containsString("state=$state"), containsString("code=")))
    }

    @Test
    fun `code convert to token`() {
      var header: String? = null
      webTestClient
        .get().uri("/oauth2/authorize?response_type=code&client_id=$validClientId&state=$state&redirect_uri=$validRedirectUri")
        .cookie("jwtSession", createAuthenticationJwt("username", "ROLE_TESTING", "ROLE_MORE_TESTING"))
        .exchange()
        .expectHeader()
        .value("Location") { h: String -> header = h }

      val authorisationCode =
        header!!.substringAfter("?").split("&").first { it.startsWith("code=") }.substringAfter("code=")

      val formData = LinkedMultiValueMap<String, String>().apply {
        add("grant_type", "authorization_code")
        add("code", authorisationCode)
        add("state", state)
        add("redirect_uri", validRedirectUri)
      }

      val tokenResponse = webTestClient
        .post().uri("/oauth2/token")
        .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(("$validClientId:test-secret").toByteArray()))
        .contentType(APPLICATION_FORM_URLENCODED)
        .bodyValue(
          formData,
        )
        .exchange()
        .expectStatus().isOk
        .expectBody()
        .returnResult().responseBody

      val token = getTokenPayload(String(tokenResponse!!))
      assertThat(token.get("authorities")).isEqualTo(JSONArray(listOf("ROLE_TESTING", "ROLE_MORE_TESTING")))
      assertThat(token.get("sub")).isEqualTo("username")
      assertThat(token.get("aud")).isEqualTo(validClientId)
    }

    private fun createAuthenticationJwt(username: String, vararg roles: String): String {
      val authoritiesAsString = roles.asList().joinToString(",")

      return Jwts.builder()
        .setId("1234")
        .setSubject(username)
        .addClaims(
          mapOf<String, Any>(
            "authorities" to authoritiesAsString,
            "name" to "name",
            "auth_source" to AuthSource.Auth.name,
            "user_id" to "9999",
            "passed_mfa" to true,
          ),
        )
        .setExpiration(Date(System.currentTimeMillis() + Duration.ofSeconds(5).toMillis()))
        .signWith(SignatureAlgorithm.RS256, jwkKeyAccessor.getPrimaryKeyPair().private)
        .compact()
    }
  }

  private fun getTokenPayload(response: String): JSONObject {
    val accessToken = JSONObject(response).get("access_token") as String
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
