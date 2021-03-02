package com.microsoft.performance.tuning.test

import io.gatling.core.Predef._
import io.gatling.http.Predef._

import scala.concurrent.duration._

class ApiGatlingSimulationPostTest extends Simulation {

  object randomStringGenerator {
    def randomString(length: Int) = scala.util.Random.alphanumeric.filter(_.isLetter).take(length).mkString
  }

  val httpProtocol = http
    .baseUrl("http://localhost:9003") // 5
    .doNotTrackHeader("1")
    .acceptLanguageHeader("en-US,en;q=0.5")
    .userAgentHeader("Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0")

  var randomSession = Iterator.continually(Map("randUserName" -> randomStringGenerator.randomString(10)))

  // 对于post请求，需要生成不同的post body，通过feed，random来给不同的数据
  val scn1 = scenario("multi-service-access").feed(randomSession).exec(
    http("register-user")
      .post("/accounts/")
      .body(StringBody("""{ "username": "${randUserName}", "password": "12345678" } """)).asJson
      .header("Content-Type", "application/json")
      .check(status.is(200))
  ).pause(100.milliseconds)

  // 逐步递增测试
  /*setUp(scn1.inject(
      incrementUsersPerSec(5) // Double
        .times(5)
        .eachLevelLasting(10 seconds)
        .separatedByRampsLasting(10 seconds)
        .startingFrom(10) // Double
    )
  )*/

  // 区间测试
  setUp(scn1.inject(rampUsersPerSec(10) to 20 during(1 minutes))).protocols(httpProtocol)
}