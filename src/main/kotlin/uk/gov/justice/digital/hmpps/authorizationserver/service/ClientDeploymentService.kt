package uk.gov.justice.digital.hmpps.authorizationserver.service

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientDeployment
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.ClientType
import uk.gov.justice.digital.hmpps.authorizationserver.data.model.Hosting
import uk.gov.justice.digital.hmpps.authorizationserver.data.repository.ClientDeploymentRepository
import uk.gov.justice.digital.hmpps.authorizationserver.resource.ClientDeploymentDetailsRequest
import uk.gov.justice.digital.hmpps.authorizationserver.utils.ClientIdConverter

@Service
class ClientDeploymentService(
  private val clientDeploymentRepository: ClientDeploymentRepository,
  private val clientIdConverter: ClientIdConverter,
) {

  @Transactional
  fun add(clientDeployment: ClientDeploymentDetailsRequest) {
    val baseClientId = clientIdConverter.toBase(clientDeployment.clientId)
    val existingClientDeployment = clientDeploymentRepository.findClientDeploymentByBaseClientId(baseClientId)
    existingClientDeployment?.let {
      throw ClientDeploymentAlreadyExistsException(clientDeployment.clientId)
    }

    clientDeploymentRepository.save(toClientDeploymentEntity(clientDeployment, baseClientId))
  }

  private fun toClientDeploymentEntity(clientDeployment: ClientDeploymentDetailsRequest, baseClientId: String): ClientDeployment {
    with(clientDeployment) {
      return ClientDeployment(
        baseClientId = baseClientId,
        clientType = clientType?.let { ClientType.valueOf(clientType) },
        team = team,
        teamContact = teamContact,
        teamSlack = teamSlack,
        hosting = hosting?.let { Hosting.valueOf(hosting) },
        namespace = namespace,
        deployment = deployment,
        secretName = secretName,
        clientIdKey = clientIdKey,
        secretKey = secretKey,
        deploymentInfo = deploymentInfo,
      )
    }
  }
}

class ClientDeploymentAlreadyExistsException(clientId: String) : RuntimeException("ClientDeployment for client id $clientId already exists")