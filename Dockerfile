# Image de base ancienne — Trivy va détecter des CVE dessus
FROM eclipse-temurin:17-jre-alpine

# Mauvaise pratique : exécuter en root (Trivy/Checkov le détecte)
# USER root  ← pas de USER défini = root par défaut

WORKDIR /app

# Copier le JAR buildé
COPY target/*.jar app.jar

# Port exposé
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]