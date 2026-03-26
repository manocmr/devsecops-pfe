pipeline {
    agent any

    tools {
        jdk 'JDK-21'
    }

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

        stage('Terraform Validate') {
            steps {
                echo 'Validation syntaxique Terraform...'
                dir('terraform') {
                    bat 'terraform init -backend=false'
                    bat 'terraform validate'
                }
            }
        }

        stage('Checkov - Terraform') {
            steps {
                echo 'Scan Terraform avec Checkov...'
                bat 'checkov -d terraform --framework terraform'
            }
        }

        stage('tfsec - Terraform') {
            steps {
                echo 'Scan Terraform avec tfsec...'
                bat 'tfsec terraform'
            }
        }

        stage('Trivy - Terraform Misconfig') {
            steps {
                echo 'Scan Terraform avec Trivy...'
                bat 'trivy config terraform --misconfig-scanners terraform --severity HIGH,CRITICAL --exit-code 1 --format table --output trivy-terraform-misconfig.txt'
            }
        }


        stage('Checkov - Kubernetes') {
            steps {
                echo 'Scan Kubernetes YAML avec Checkov...'
                bat 'checkov -d kubernetes --framework kubernetes'
            }
        }

        stage('Validate Kubernetes YAML') {
            steps {
                echo 'Validation des manifests Kubernetes...'
                bat 'kubectl apply --dry-run=client -f kubernetes'
            }
        }

        stage('Trivy - Kubernetes Misconfig') {
            steps {
                echo 'Scan Kubernetes YAML avec Trivy...'
                bat 'trivy config kubernetes --severity HIGH,CRITICAL --exit-code 1 --format table --output trivy-k8s-misconfig.txt'
            }
        }

        stage('Build Docker Image') {
            steps {
                bat "docker build -t %IMAGE_NAME%:%IMAGE_TAG% ."
            }
        }

        stage('Trivy - Rapport CVE HIGH/CRITICAL') {
            steps {
                echo 'Detection des CVE HIGH et CRITICAL...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity HIGH,CRITICAL --exit-code 0 --format table --output trivy-cve-report.txt"
            }
        }

        stage('Trivy - Rapport CVE CRITICAL') {
            steps {
                echo 'Detection des CVE CRITICAL...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity CRITICAL --exit-code 0 --format table --output trivy-critical-report.txt"
            }
        }

        stage('Trivy - Rapport Licences') {
            steps {
                echo 'Detection des licences...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners license --exit-code 0 --format table --output trivy-license-report.txt"
            }
        }

        stage('Trivy - Mauvaises Configurations') {
            steps {
                echo 'Detection des mauvaises configurations...'
                bat "trivy config . --exit-code 0 --severity HIGH,CRITICAL --format table --output trivy-misconfig-report.txt"
            }
        }

        stage('Trivy - Rapport JSON Global') {
            steps {
                echo 'Generation du rapport JSON complet...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --format json --output trivy-full-report.json"
            }
        }

        stage('Trivy - Blocage Final') {
            steps {
                echo 'Blocage pipeline si CVE CRITICAL detectee...'
                bat "trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity CRITICAL --exit-code 1 --format table"
            }
        }

        stage('Deploy') {
            steps {
                echo 'Aucune violation critique - deploiement autorise'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'trivy-*.txt, trivy-*.json', allowEmptyArchive: true
        }
        failure {
            echo 'ECHEC - violation de securite detectee - pipeline bloque !'
        }
        success {
            echo 'SUCCES - pipeline DevSecOps conforme !'
        }
    }
}