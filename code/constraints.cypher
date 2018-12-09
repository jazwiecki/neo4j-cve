// uniqueness constraints implicitly create indexes
CREATE CONSTRAINT ON (cve:CVE) ASSERT cve.name IS UNIQUE;
CREATE CONSTRAINT ON (attack_vector:AttackVector) ASSERT attack_vector.name IS UNIQUE;
CREATE CONSTRAINT ON (vendor:Vendor) ASSERT vendor.name IS UNIQUE;
CREATE CONSTRAINT ON (product:Product) ASSERT product.name IS UNIQUE;
CREATE CONSTRAINT ON (product_version:ProductVersion) ASSERT product_version.name IS UNIQUE;