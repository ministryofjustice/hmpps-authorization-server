package uk.gov.justice.digital.hmpps.authorizationserver.resource

import com.microsoft.applicationinsights.TelemetryClient
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.core.convert.ConversionService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.ResponseStatus
import uk.gov.justice.digital.hmpps.authorizationserver.config.AuthenticationFacade
import uk.gov.justice.digital.hmpps.authorizationserver.config.trackEvent
import uk.gov.justice.digital.hmpps.authorizationserver.service.ClientIdService
import uk.gov.justice.digital.hmpps.authorizationserver.service.MigrationClientService

@Controller
class MigrationController(
  private val migrationClientService: MigrationClientService,
  private val conversionService: ConversionService,
  private val telemetryClient: TelemetryClient,
  private val authenticationFacade: AuthenticationFacade,
  private val clientIdService: ClientIdService,
) {

  @PostMapping("migrate-client")
  @ResponseStatus(HttpStatus.OK)
  @PreAuthorize("hasRole('ROLE_OAUTH_ADMIN')")
  fun addClient(
    @Valid @RequestBody
    clientDetails: MigrationClientRequest,
  ): ResponseEntity<Any> {
    val registrationResponse = migrationClientService.addClient(clientDetails)
    val telemetryMap = mapOf("username" to authenticationFacade.currentUsername!!, "clientId" to clientDetails.clientId!!)
    telemetryClient.trackEvent("AuthorizationServerDetailsMigrate", telemetryMap)
    return ResponseEntity.ok(registrationResponse)
  }
}

class MigrationClientRequest(
  @field:NotBlank(message = "clientId must not be blank")
  @field:Size(max = 100, message = "clientId max size is 100")
  val clientId: String?,
  val scopes: List<String>?,
  val authorities: List<String>?,
  val ips: List<String>?,
  val jiraNumber: String?,
  val databaseUserName: String?,
  val validDays: Long?,
  val accessTokenValidityMinutes: Long?,
  val clientSecret: String,
  val clientDeploymentDetails: ClientDeploymentDetails?,
) // : ClientRegistrationRequest(clientId,scopes,authorities,ips,jiraNumber,databaseUserName,validDays,accessTokenValidityMinutes)
