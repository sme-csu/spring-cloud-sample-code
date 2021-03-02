# Introduction 
deploy the spring cloud micro-services to kubernetes 

# Getting Started
1.	add spring-cloud-kubernetes dependecy
2.	add dekorate dependecy to generte yaml files
3.	add jib-plugin to build docker image
4.	deploy resource to kuberent cluster by kubectl

# Build and Test
1. mvn compile package
2. get the xx-service/target/classes/META-INF/dekorate/kubernetes.yml, then change role and so on.
3. kubectl apply -f kubernetes.yml 

# gatling test
Testing is done with the Maven Gatling plugin, which is well integrated with CICD.
1. mvn  gatling:test
