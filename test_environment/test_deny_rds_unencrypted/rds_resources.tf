# RDS Test Resources for deny_rds_unencrypted SCP Testing
#
# These resources test the RDS encryption check across instances and clusters.
# WARNING: These resources incur AWS charges. Destroy when not in use.

# RDS Instance 1: Encrypted PostgreSQL instance (COMPLIANT)
resource "aws_db_instance" "encrypted_instance" {
  provider = aws.acme_co

  identifier     = "encrypted-instance"
  engine         = "postgres"
  engine_version = "14.17"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = true

  db_name  = "testdb"
  username = "dbadmin"
  password = "ChangeMeP1ease!" # pragma: allowlist secret

  skip_final_snapshot = true
  deletion_protection = false

  tags = {
    Name        = "encrypted-instance"
    TestPurpose = "deny_rds_unencrypted_check"
    Compliance  = "compliant"
  }
}

# RDS Instance 2: Unencrypted MySQL instance (VIOLATION)
resource "aws_db_instance" "unencrypted_instance" {
  provider = aws.shared_foo_bar

  identifier     = "unencrypted-instance"
  engine         = "mysql"
  engine_version = "8.0.40"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_type      = "gp2"
  storage_encrypted = false

  db_name  = "testdb"
  username = "dbadmin"
  password = "ChangeMeP1ease!" # pragma: allowlist secret

  skip_final_snapshot = true
  deletion_protection = false

  tags = {
    Name        = "unencrypted-instance"
    TestPurpose = "deny_rds_unencrypted_check"
    Compliance  = "violation"
  }
}

# Aurora Cluster 1: Encrypted Aurora MySQL cluster (COMPLIANT)
resource "aws_rds_cluster" "encrypted_cluster" {
  provider = aws.fort_knox

  cluster_identifier = "encrypted-cluster"
  engine             = "aurora-mysql"
  engine_version     = "8.0.mysql_aurora.3.04.0"
  engine_mode        = "provisioned"

  database_name   = "testdb"
  master_username = "dbadmin"
  master_password = "ChangeMeP1ease!" # pragma: allowlist secret

  storage_encrypted = true

  skip_final_snapshot = true
  deletion_protection = false

  tags = {
    Name        = "encrypted-cluster"
    TestPurpose = "deny_rds_unencrypted_check"
    Compliance  = "compliant"
  }
}

# Aurora Cluster Instance for encrypted cluster
resource "aws_rds_cluster_instance" "encrypted_cluster_instance" {
  provider = aws.fort_knox

  identifier         = "encrypted-cluster-instance-1"
  cluster_identifier = aws_rds_cluster.encrypted_cluster.id
  instance_class     = "db.t3.medium"
  engine             = aws_rds_cluster.encrypted_cluster.engine
  engine_version     = aws_rds_cluster.encrypted_cluster.engine_version

  tags = {
    Name        = "encrypted-cluster-instance-1"
    TestPurpose = "deny_rds_unencrypted_check"
  }
}

# Aurora Cluster 2: Unencrypted Aurora PostgreSQL cluster (VIOLATION)
resource "aws_rds_cluster" "unencrypted_cluster" {
  provider = aws.acme_co

  cluster_identifier = "unencrypted-cluster"
  engine             = "aurora-postgresql"
  engine_version     = "14.18"
  engine_mode        = "provisioned"

  database_name   = "testdb"
  master_username = "dbadmin"
  master_password = "ChangeMeP1ease!" # pragma: allowlist secret

  storage_encrypted = false

  skip_final_snapshot = true
  deletion_protection = false

  tags = {
    Name        = "unencrypted-cluster"
    TestPurpose = "deny_rds_unencrypted_check"
    Compliance  = "violation"
  }
}

# Aurora Cluster Instance for unencrypted cluster
resource "aws_rds_cluster_instance" "unencrypted_cluster_instance" {
  provider = aws.acme_co

  identifier         = "unencrypted-cluster-instance-1"
  cluster_identifier = aws_rds_cluster.unencrypted_cluster.id
  instance_class     = "db.t3.medium"
  engine             = aws_rds_cluster.unencrypted_cluster.engine
  engine_version     = aws_rds_cluster.unencrypted_cluster.engine_version

  tags = {
    Name        = "unencrypted-cluster-instance-1"
    TestPurpose = "deny_rds_unencrypted_check"
  }
}
