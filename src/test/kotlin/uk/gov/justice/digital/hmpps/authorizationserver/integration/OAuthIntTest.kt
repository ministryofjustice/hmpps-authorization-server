package uk.gov.justice.digital.hmpps.authorizationserver.integration

import com.microsoft.applicationinsights.TelemetryClient
import org.assertj.core.api.Assertions.assertThat
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.kotlin.verify
import org.springframework.boot.test.mock.mockito.MockBean
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.reactive.function.BodyInserters.fromFormData
import java.util.*

class OAuthIntTest : IntegrationTestBase() {

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

  private fun getTokenPayload(response: String): JSONObject {
    val accessToken = JSONObject(response).get("access_token") as String
    val tokenParts = accessToken.split(".")
    return JSONObject(String(Base64.getDecoder().decode(tokenParts[1])))
  }
}
