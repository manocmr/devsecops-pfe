pipeline {
    agent any

    environment {
        IMAGE_NAME = "devsecops-pipeline-test"
        IMAGE_TAG  = "latest"
        CVSS_THRESHOLD = "7.0"
    }

    stages {

        stage('Build App') {
            steps {
                sh 'mvn clean package -DskipTests'
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${IMAGE_NAME}:${IMAGE_TAG} ."
            }
        }

        // ─── TRIVY SCANS ────────────────────────────────────────

        stage('Trivy — Scan Filesystem & Secrets') {
            steps {
                echo 'Scan du code source et des fichiers de config...'
                sh """
                    trivy fs . \
                        --scanners vuln,secret,misconfig \
                        --severity HIGH,CRITICAL \
                        --exit-code 1 \
                        --format table
                """
            }
        }

        stage('Trivy — Scan Image Docker') {
            steps {
                echo 'Scan des CVE dans l image Docker...'
                sh """
                    trivy image ${IMAGE_NAME}:${IMAGE_TAG} \
                        --scanners vuln,misconfig \
                        --severity HIGH,CRITICAL \
                        --exit-code 1 \
                        --cvss-score-threshold ${CVSS_THRESHOLD} \
                        --format table \
                        --output trivy-report.txt
                """
            }
        }

        stage('Trivy — Rapport JSON') {
            steps {
                echo 'Génération du rapport JSON pour archivage...'
                sh """
                    trivy image ${IMAGE_NAME}:${IMAGE_TAG} \
                        --scanners vuln \
                        --severity HIGH,CRITICAL \
                        --format json \
                        --output trivy-report.json
                """
            }
        }

        // ────────────────────────────────────────────────────────

        stage('Deploy') {
            when {
                expression { currentBuild.result == null }
            }
            steps {
                echo 'Aucune CVE critique — déploiement autorisé ✅'
            }
        }
    }

    post {
        always {
            // Archiver les rapports même si le pipeline échoue
            archiveArtifacts artifacts: 'trivy-report.*', allowEmptyArchive: true
        }
        failure {
            echo '❌ CVE critique détectée — pipeline bloqué !'
            // Ici tu peux ajouter une alerte Slack/Email
        }
        success {
            echo '✅ Aucune misconfiguration critique détectée !'
        }
    }
}
```

---

## Ce que Trivy va détecter sur ton projet

| Type | Ce qui est scanné |
|---|---|
| **CVE critiques** | Vulnérabilités dans l'image `eclipse-temurin:17` |
| **Packages obsolètes** | Librairies Alpine/Java avec CVE connues |
| **Secrets** | Mots de passe, tokens hardcodés dans le code |
| **Misconfigs** | Pas de USER défini, EXPOSE inutile, etc. |

---

## Résumé des fichiers à avoir
```
devsecops-pipeline-test/
├── Dockerfile        ✅ déjà créé
├── .trivy.yaml       ✅ nouveau
├── .trivyignore      ✅ nouveau
└── Jenkinsfile       ✅ mis à jour