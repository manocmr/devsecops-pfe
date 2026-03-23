pipeline {
    agent any

    environment {
        IMAGE_NAME = "devsecops-pipeline-test"
        IMAGE_TAG  = "latest"
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

        stage('Trivy - CVE Critiques') {
            steps {
                echo 'Detection des CVE HIGH et CRITICAL...'
                sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --format table --output trivy-cve-report.txt"
            }
        }

        stage('Trivy - Seuil CVSS') {
            steps {
                echo 'Blocage si score CVSS superieur a 7.0...'
                sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --scanners vuln --severity HIGH,CRITICAL --cvss-score-threshold 7.0 --exit-code 1 --format table"
            }
        }

        stage('Trivy - Packages Obsoletes') {
            steps {
                echo 'Detection des packages obsoletes et licences...'
                sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --scanners license --severity HIGH,CRITICAL --exit-code 0 --format table --output trivy-packages-report.txt"
            }
        }

        stage('Trivy - Mauvaises Pratiques Dockerfile') {
            steps {
                echo 'Detection des mauvaises configurations Docker...'
                sh "trivy config . --exit-code 1 --severity HIGH,CRITICAL --format table --output trivy-misconfig-report.txt"
            }
        }

        stage('Trivy - Rapport JSON Global') {
            steps {
                echo 'Generation rapport JSON complet...'
                sh "trivy image ${IMAGE_NAME}:${IMAGE_TAG} --scanners vuln,misconfig,secret,license --severity HIGH,CRITICAL --format json --output trivy-full-report.json"
            }
        }

        stage('Deploy') {
            steps {
                echo 'Aucune CVE critique - deploiement autorise'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'trivy-*.txt, trivy-*.json', allowEmptyArchive: true
        }
        failure {
            echo 'ECHEC - Vulnerability ou misconfiguration critique detectee !'
        }
        success {
            echo 'SUCCES - Image Docker conforme et securisee !'
        }
    }
}