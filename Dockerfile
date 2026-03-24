FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

RUN apk update && apk upgrade --no-cache

COPY target/*.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]