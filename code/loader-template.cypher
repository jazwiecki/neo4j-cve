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
SET cve.description = [desc IN vuln.cve.description.description_data WHERE desc.lang = 'en'| desc.value],
    cve.published = apoc.date.fromISO8601(apoc.text.replace(vuln.publishedDate,'Z$',':00Z')),
    cve.`v2.access_complexity` = vuln.impact.baseMetricV2.cvssV2.accessComplexity,
    cve.`v2.authentication` = vuln.impact.baseMetricV2.cvssV2.authentication,
    cve.`v2.availability_impact` = vuln.impact.baseMetricV2.cvssV2.availabilityImpact,
    cve.`v2.base_score` = vuln.impact.baseMetricV2.cvssV2.baseScore,
    cve.`v2.confidentiality_impact` = vuln.impact.baseMetricV2.cvssV2.confidentialityImpact,
    cve.`v2.exploitability_score` = vuln.impact.baseMetricV2.exploitabilityScore,
    cve.`v2.impact_score` = vuln.impact.baseMetricV2.impactScore,
    cve.`v2.integrity_impact` = vuln.impact.baseMetricV2.cvssV2.integrityImpact,
    cve.`v2.severity` = vuln.impact.baseMetricV2.severity,
    cve.`v2.obtain_all_privilege` = vuln.impact.baseMetricV2.obtainAllPrivilege,
    cve.`v2.obtain_other_privilege` = vuln.impact.baseMetricV2.obtainOtherPrivilege,
    cve.`v2.obtain_user_privilege` = vuln.impact.baseMetricV2.obtainUserPrivilege,
    cve.`v2.user_interaction_required` = vuln.impact.baseMetricV2.userInteractionRequired,
    cve.`v2.vector_string` = vuln.impact.baseMetricV2.cvssV2.vectorString,
    cve.`v3.attack_complexity` = vuln.impact.baseMetricV3.cvssV3.attackComplexity,
    cve.`v3.availability_impact` = vuln.impact.baseMetricV3.cvssV3.availabilityImpact,
    cve.`v3.base_score` = vuln.impact.baseMetricV3.cvssV3.baseScore,
    cve.`v3.base_severity` = vuln.impact.baseMetricV3.cvssV3.baseSeverity,
    cve.`v3.confidentiality_impact` = vuln.impact.baseMetricV3.cvssV3.confidentialityImpact,
    cve.`v3.exploitability_score` = vuln.impact.baseMetricV3.exploitabilityScore,
    cve.`v3.impact_score` = vuln.impact.baseMetricV3.impactScore,
    cve.`v3.integrity_impact` = vuln.impact.baseMetricV3.cvssV3.integrityImpact,
    cve.`v3.privileges_required` = vuln.impact.baseMetricV3.cvssV3.privilegesRequired,
    cve.`v3.scope` = vuln.impact.baseMetricV3.cvssV3.scope,
    cve.`v3.user_interaction` = vuln.impact.baseMetricV3.cvssV3.userInteraction,
    cve.`v3.vector_string` = vuln.impact.baseMetricV3.cvssV3.vectorString

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