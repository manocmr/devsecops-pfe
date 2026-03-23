pipeline {
    agent any

    environment {
        IMAGE_NAME = "devsecops-pipeline-test"
        IMAGE_TAG  = "latest"
    }

    stages {

        stage('Build App') {
            steps {
                bat 'mvn clean package -DskipTests'
            }
        }

        stage('Build Docker Image') {
            steps {
                bat "docker build -t %IMAGE_NAME%:%IMAGE_TAG% ."
            }
        }

        stage('Trivy - CVE Critiques') {
            steps {
                echo 'Detection des CVE HIGH et CRITICAL...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity HIGH,CRITICAL --exit-code 0 --format table --output trivy-cve-report.txt"
            }
        }

        stage('Trivy - Seuil CVSS') {
            steps {
                echo 'Blocage pipeline si CVE CRITICAL detectee...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity CRITICAL --exit-code 1 --format table"
            }
        }

        stage('Trivy - Packages Obsoletes') {
            steps {
                echo 'Detection des packages obsoletes...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners license --exit-code 0 --format table --output trivy-packages-report.txt"
            }
        }

        stage('Trivy - Mauvaises Pratiques Dockerfile') {
            steps {
                echo 'Detection des mauvaises configurations Docker...'
                bat "trivy config . --exit-code 0 --severity HIGH,CRITICAL --format table --output trivy-misconfig-report.txt"
            }
        }

        stage('Trivy - Rapport JSON Global') {
            steps {
                echo 'Generation rapport JSON complet...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --format json --output trivy-full-report.json"
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
            echo 'ECHEC - CVE critique detectee - pipeline bloque !'
        }
        success {
            echo 'SUCCES - Image Docker conforme et securisee !'
        }
    }
    tools {
    jdk 'JDK-21'
    }
}