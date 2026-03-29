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

        stage('IaC Scan - Checkov') {
            steps {
                echo 'Scan Terraform avec Checkov...'
                bat 'checkov -d terraform --framework terraform'
                echo 'Scan Kubernetes YAML avec Checkov...'
                bat 'checkov -d kubernetes --framework kubernetes'
            }
        }

        stage('IaC Scan - Tfsec') {
            steps {
                echo 'Scan Terraform avec tfsec...'
                bat 'tfsec terraform'
            }
        }

        stage('IaC Scan - Terrascan') {
            steps {
                echo 'Scan IaC avec Terrascan...'
                bat 'terrascan scan -i terraform -d terraform'
                bat 'terrascan scan -i k8s -d kubernetes'
            }
        }

        stage('IaC Scan - Trivy') {
            steps {
                echo 'Scan Terraform & K8s avec Trivy...'
                bat 'trivy config terraform --severity HIGH,CRITICAL --exit-code 1'
                bat 'trivy config kubernetes --severity HIGH,CRITICAL --exit-code 1'
            }
        }

        stage('Validate Kubernetes YAML') {
            steps {
                echo 'Validation des manifests Kubernetes...'
                bat 'kubectl apply --dry-run=client -f kubernetes'
            }
        }

        stage('Build Docker Image') {
            steps {
                bat 'docker build -t %IMAGE_NAME%:%IMAGE_TAG% .'
            }
        }

        stage('Docker Scan - Trivy') {
            steps {
                echo 'Detection des mauvaises pratiques et obsolescences (Trivy Config/Vuln)...'
                bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners misconfig,secret --severity HIGH,CRITICAL --format table --exit-code 1'
                
                echo 'Generation du rapport complet (optionnel pour logs)...'
                bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln,misconfig,secret --format json --output trivy-full-report.json'
                
                echo 'Blocage pipeline si CVE CRITICAL ou HIGH detectee...'
                bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity HIGH,CRITICAL --exit-code 1'
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