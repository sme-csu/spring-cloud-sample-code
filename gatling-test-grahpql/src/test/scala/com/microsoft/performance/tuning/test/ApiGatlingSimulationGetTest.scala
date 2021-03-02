package com.microsoft.performance.tuning.test

import io.gatling.core.Predef.{exec, _}
import io.gatling.http.Predef._

import scala.concurrent.duration._

class ApiGatlingSimulationGetTest extends Simulation {

  object randomStringGenerator {
    def randomString(length: Int) = scala.util.Random.alphanumeric.filter(_.isLetter).take(length).mkString
  }

  val httpProtocol = http
    .baseUrl("http://localhost:8887") // 5
    .doNotTrackHeader("1")
    .acceptLanguageHeader("en-US,en;q=0.5")
    .userAgentHeader("Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0")

  // 对于get请求，可以直接重复
  val scn2 = scenario("multi-service-access").repeat(1000, "n") {
    exec(
      http("health check")
        .get("/actuator/health")
        .header("Content-Type", "application/json")
        .check(status.is(200))
    ).pause(10.milliseconds)
  }

  setUp(scn2.inject(atOnceUsers(50))).maxDuration(FiniteDuration.apply(1, "minutes")).protocols(httpProtocol)

}