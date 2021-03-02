/*
package com.microsoft.performance.tuning.test

import io.gatling.core.Predef.{exec, _}
import io.gatling.http.Predef._

import scala.concurrent.duration._

class ApiGatlingSimulationTest extends Simulation {

  object randomStringGenerator {
    def randomString(length: Int) = scala.util.Random.alphanumeric.filter(_.isLetter).take(length).mkString
  }

  val httpProtocol = http
    .baseUrl("http://localhost:8887") // 5
    .doNotTrackHeader("1")
    .acceptLanguageHeader("en-US,en;q=0.5")
    .userAgentHeader("Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0")

  var randomSession = Iterator.continually(Map("randsession" -> randomStringGenerator.randomString(10)))

  // 对于post请求，需要生成不同的post body，通过feed，random来给不同的数据
  val scn1 = scenario("multi-service-access").feed(randomSession).exec(
    http("register-user")
      .post("/accounts/")
      .body(StringBody("""${randsession}"""))
      .header("Content-Type", "application/json")
      .check(status.is(200))
    ).pause(100.milliseconds)

  setUp(scn1.inject(atOnceUsers(50))).maxDuration(FiniteDuration.apply(5, "minutes")).protocols(httpProtocol)


  // 对于get请求，可以直接重复
  val scn2 = scenario("multi-service-access").repeat(1000, "n") {
    exec(
      http("health check")
        .get("/actuator/health")
        .header("Content-Type", "application/json")
        .check(status.is(200))
    ).pause(10.milliseconds)
  }

  setUp(scn2.inject(atOnceUsers(50))).maxDuration(FiniteDuration.apply(5, "minutes")).protocols(httpProtocol)

}*/
