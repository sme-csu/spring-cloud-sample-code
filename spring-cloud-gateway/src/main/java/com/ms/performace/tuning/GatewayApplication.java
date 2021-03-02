package com.ms.performace.tuning;

import io.dekorate.kubernetes.annotation.KubernetesApplication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.netflix.hystrix.EnableHystrix;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

@EnableDiscoveryClient
@EnableHystrix
@RestController
@SpringBootApplication
@KubernetesApplication
public class GatewayApplication {

    public static void main(String[] args) {

        SpringApplication.run(GatewayApplication.class, args);
    }

    // 定义服务发现客户端
    @Autowired
    private DiscoveryClient discoveryClient;


    // 获取kubernetes 集群中的service， 是不是很简单，以后可以使用kubernetes 服务发现了
    @RequestMapping("/test/services")
    public List<String> Services() {

        return this.discoveryClient.getServices();
    }


    // Not
    @Bean
    KeyResolver userKeyResolver() {
        return exchange -> Mono.just("fero");
    }
}
