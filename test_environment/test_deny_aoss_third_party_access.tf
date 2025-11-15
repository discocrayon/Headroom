# What is the point of RCPs on AOSS if data access policies do not support cross-account access?


# # Test OpenSearch Serverless collections for deny_aoss_third_party_access RCP testing
# # These resources demonstrate AOSS data access policies with third-party account access

# # Note: OpenSearch Serverless collections have ongoing costs
# # Cost warning: AOSS collections cost approximately $700/month minimum per collection
# # These test resources should be created only when needed and destroyed immediately after testing

# # Collection 1: Collection with third-party access (Vendor A)
# # This collection has a data access policy allowing a third-party account

# # Encryption policy for vendor-a (required before creating collection)
# resource "aws_opensearchserverless_security_policy" "third_party_vendor_a_encryption" {
#   provider = aws.acme_co
#   name     = "vendor-a-encryption"
#   type     = "encryption"

#   policy = jsonencode({
#     Rules = [
#       {
#         ResourceType = "collection"
#         Resource     = ["collection/vendor-a"]
#       }
#     ]
#     AWSOwnedKey = true
#   })
# }

# # Network policy for vendor-a
# resource "aws_opensearchserverless_security_policy" "third_party_vendor_a_network" {
#   provider = aws.acme_co
#   name     = "vendor-a-network"
#   type     = "network"

#   policy = jsonencode([
#     {
#       Rules = [
#         {
#           ResourceType = "collection"
#           Resource     = ["collection/vendor-a"]
#         }
#       ]
#       AllowFromPublic = true
#     }
#   ])
# }

# resource "aws_opensearchserverless_collection" "third_party_vendor_a" {
#   provider   = aws.acme_co
#   name       = "vendor-a"
#   type       = "SEARCH"
#   depends_on = [aws_opensearchserverless_security_policy.third_party_vendor_a_encryption]

#   tags = {
#     Purpose = "Headroom AOSS third-party access test - Vendor A"
#   }
# }

# # Access policy for Collection 1: Allow third-party account 999888777666
# resource "aws_opensearchserverless_access_policy" "third_party_vendor_a" {
#   provider = aws.acme_co
#   name     = "vendor-a"
#   type     = "data"

#   policy = jsonencode([{
#     Rules = [
#       {
#         Resource = ["collection/${aws_opensearchserverless_collection.third_party_vendor_a.name}"]
#         Permission = [
#           "aoss:DescribeCollection",
#           "aoss:ReadDocument",
#           "aoss:WriteDocument"
#         ]
#         ResourceType = "collection"
#       },
#       {
#         Resource = ["index/${aws_opensearchserverless_collection.third_party_vendor_a.name}/*"]
#         Permission = [
#           "aoss:CreateIndex",
#           "aoss:ReadDocument",
#           "aoss:WriteDocument",
#           "aoss:UpdateIndex"
#         ]
#         ResourceType = "index"
#       }
#     ]
#     Principal = [
#       "arn:aws:iam::999888777666:root"
#     ]
#   }])
# }

# # Collection 2: Collection with multiple third-party accounts (Vendors B and C)
# # This demonstrates a collection accessible by multiple third-party accounts

# # Encryption policy for multi-vendor (required before creating collection)
# resource "aws_opensearchserverless_security_policy" "multi_third_party_encryption" {
#   provider = aws.shared_foo_bar
#   name     = "multi-vendor-encryption"
#   type     = "encryption"

#   policy = jsonencode({
#     Rules = [
#       {
#         ResourceType = "collection"
#         Resource     = ["collection/multi-vendor"]
#       }
#     ]
#     AWSOwnedKey = true
#   })
# }

# # Network policy for multi-vendor
# resource "aws_opensearchserverless_security_policy" "multi_third_party_network" {
#   provider = aws.shared_foo_bar
#   name     = "multi-vendor-network"
#   type     = "network"

#   policy = jsonencode([
#     {
#       Rules = [
#         {
#           ResourceType = "collection"
#           Resource     = ["collection/multi-vendor"]
#         }
#       ]
#       AllowFromPublic = true
#     }
#   ])
# }

# resource "aws_opensearchserverless_collection" "multi_third_party" {
#   provider   = aws.shared_foo_bar
#   name       = "multi-vendor"
#   type       = "SEARCH"
#   depends_on = [aws_opensearchserverless_security_policy.multi_third_party_encryption]

#   tags = {
#     Purpose = "Headroom AOSS third-party access test - Multiple vendors"
#   }
# }

# # Access policy for Collection 2: Allow multiple third-party accounts
# resource "aws_opensearchserverless_access_policy" "multi_third_party" {
#   provider = aws.shared_foo_bar
#   name     = "multi-vendor"
#   type     = "data"

#   policy = jsonencode([{
#     Rules = [
#       {
#         Resource = ["collection/${aws_opensearchserverless_collection.multi_third_party.name}"]
#         Permission = [
#           "aoss:DescribeCollection",
#           "aoss:ReadDocument"
#         ]
#         ResourceType = "collection"
#       }
#     ]
#     Principal = [
#       "arn:aws:iam::111222333444:root",
#       "arn:aws:iam::555666777888:root"
#     ]
#   }])
# }

# # Collection 3: Org-only access (should not appear in results)
# # This collection only has access policies for organization accounts

# # Encryption policy for org-only (required before creating collection)
# resource "aws_opensearchserverless_security_policy" "org_only_encryption" {
#   provider = aws.fort_knox
#   name     = "org-only-encryption"
#   type     = "encryption"

#   policy = jsonencode({
#     Rules = [
#       {
#         ResourceType = "collection"
#         Resource     = ["collection/org-only"]
#       }
#     ]
#     AWSOwnedKey = true
#   })
# }

# # Network policy for org-only
# resource "aws_opensearchserverless_security_policy" "org_only_network" {
#   provider = aws.fort_knox
#   name     = "org-only-network"
#   type     = "network"

#   policy = jsonencode([
#     {
#       Rules = [
#         {
#           ResourceType = "collection"
#           Resource     = ["collection/org-only"]
#         }
#       ]
#       AllowFromPublic = true
#     }
#   ])
# }

# resource "aws_opensearchserverless_collection" "org_only" {
#   provider   = aws.fort_knox
#   name       = "org-only"
#   type       = "SEARCH"
#   depends_on = [aws_opensearchserverless_security_policy.org_only_encryption]

#   tags = {
#     Purpose = "Headroom AOSS test - Org-only access"
#   }
# }

# # Access policy for Collection 3: Only allow organization accounts
# # This should NOT be detected as third-party access
# resource "aws_opensearchserverless_access_policy" "org_only" {
#   provider = aws.fort_knox
#   name     = "org-only"
#   type     = "data"

#   policy = jsonencode([{
#     Rules = [
#       {
#         Resource = ["collection/${aws_opensearchserverless_collection.org_only.name}"]
#         Permission = ["aoss:*"]
#         ResourceType = "collection"
#       }
#     ]
#     # Use organization account IDs from the organization
#     Principal = [
#       for account in data.aws_organizations_organization.current.accounts : "arn:aws:iam::${account.id}:root"
#     ]
#   }])
# }
