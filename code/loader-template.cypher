// uniqueness constraints implicitly create indexes
CREATE CONSTRAINT ON (cve:CVE) ASSERT cve.name IS UNIQUE;
CREATE CONSTRAINT ON (attack_vector:AttackVector) ASSERT attack_vector.name IS UNIQUE;
CREATE CONSTRAINT ON (vendor:Vendor) ASSERT vendor.name IS UNIQUE;
CREATE CONSTRAINT ON (product:Product) ASSERT product.name IS UNIQUE;
CREATE CONSTRAINT ON (product_version:ProductVersion) ASSERT product_version.name IS UNIQUE;

// explicitly create other non-unique indices on CVE
// we are going to create a lot b/c, as a research
// tool this should have a lot of potential entry points
// (e.g. search might start w/ all CVEs that do not require
// user interaction, or have a base_score over 9.)
// *Not* creating an index on the CVE text description,
// because this is not a document store, and if you want
// full text search to find your CVEs, you should probably
// use nvd.nist.gov.
CREATE INDEX ON :CVE(attack_complexity);
CREATE INDEX ON :CVE(availability_impact);
CREATE INDEX ON :CVE(base_score);
CREATE INDEX ON :CVE(base_severity);
CREATE INDEX ON :CVE(confidentiality_impact);
CREATE INDEX ON :CVE(exploitability_score);
CREATE INDEX ON :CVE(impact_score);
CREATE INDEX ON :CVE(integrity_impact);
CREATE INDEX ON :CVE(privileges_required);
CREATE INDEX ON :CVE(published);
CREATE INDEX ON :CVE(scope);
CREATE INDEX ON :CVE(user_interaction);
CREATE INDEX ON :CVE(vector_string);
CREATE INDEX ON :CVE(`v2.vector_string`);

// the 'nvd_file_name' string below will be replaced by the loader script
// for each file
CALL apoc.load.json('file:///var/lib/neo4j/$nvd_file_name') YIELD value AS nvd
UNWIND nvd.CVE_Items as vuln

// MERGE should be run only on the _unique_ properties for a node,
// specified in the MERGE argument, so if we run the loader again on an
// existing neo4j database, and some non-unique property (score etc)
// has changed, we want to update that property. Otherwise, Neo4j will
// try to create a new node b/c the changed properties do not match the
// existing node for a given CVE ID, then fail b/c we're violating the
// uniqueness constraint
MERGE (cve:CVE { name: vuln.cve.CVE_data_meta.ID })
SET cve.attack_complexity = COALESCE(vuln.impact.baseMetricV3.cvssV3.attackComplexity, 'NA'),
    cve.availability_impact = COALESCE(vuln.impact.baseMetricV3.cvssV3.availabilityImpact, 'NA'),
    cve.base_score = COALESCE(vuln.impact.baseMetricV3.cvssV3.baseScore, -1),
    cve.base_severity = COALESCE(vuln.impact.baseMetricV3.cvssV3.baseSeverity, 'NA'),
    cve.confidentiality_impact = COALESCE(vuln.impact.baseMetricV3.cvssV3.confidentialityImpact, 'NA'),
    cve.description = [desc IN vuln.cve.description.description_data WHERE desc.lang = 'en'| desc.value],
    cve.exploitability_score = COALESCE(vuln.impact.baseMetricV3.exploitabilityScore, -1),
    cve.impact_score = COALESCE(vuln.impact.baseMetricV3.impactScore, -1),
    cve.integrity_impact = COALESCE(vuln.impact.baseMetricV3.cvssV3.integrityImpact, 'NA'),
    cve.privileges_required = COALESCE(vuln.impact.baseMetricV3.cvssV3.privilegesRequired, 'NA'),
    cve.published = apoc.date.fromISO8601(apoc.text.replace(vuln.publishedDate,'Z$',':00Z')),
    cve.scope = COALESCE(vuln.impact.baseMetricV3.cvssV3.scope, 'NA'),
    cve.user_interaction = COALESCE(vuln.impact.baseMetricV3.cvssV3.userInteraction, 'NA')
    cve.vector_string = apoc.text.replace(COALESCE(vuln.impact.baseMetricV3.cvssV3.vectorString, 'NA'),'CVSS:3.0/',''),
    cve.`v2.vector_string` = COALESCE(vuln.impact.baseMetricV2.cvssV2.vectorString, 'NA')

FOREACH (cve_attack_vector IN vuln.impact.baseMetricV3.cvssV3.attackVector |
    MERGE (attack_vector:AttackVector {name: cve_attack_vector})
    MERGE (cve)-[:ATTACKABLE_THROUGH {cvss_version: 3}]->(attack_vector)
    )

FOREACH (cve_access_vector IN vuln.impact.baseMetricV2.cvssV2.accessVector |
    MERGE (access_vector:AttackVector {name: cve_access_vector})
    MERGE (cve)-[:ATTACKABLE_THROUGH {cvss_version: 2}]->(access_vector)
    )

FOREACH (vendor_data IN vuln.cve.affects.vendor.vendor_data |
        MERGE (vendor:Vendor {name: vendor_data.vendor_name})

        FOREACH (product_data IN vendor_data.product.product_data |
            MERGE (product:Product {name: product_data.product_name})
            MERGE (product)-[:MADE_BY]->(vendor)

            FOREACH (version_data IN product_data.version.version_data |
                MERGE (product_version:ProductVersion {
                    name: vendor_data.vendor_name + '_' + product_data.product_name + '_' + version_data.version_affected + version_data.version_value,
                    version_value: version_data.version_value
                    })
                MERGE (product_version)-[:VERSION_OF]->(product)
                MERGE (cve)-[:AFFECTS]->(product_version))
            )
    );