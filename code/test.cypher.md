CREATE CONSTRAINT ON (cve:CVE) ASSERT cve.name IS UNIQUE;
CREATE CONSTRAINT ON (cvss:CVSS) ASSERT cvss.name IS UNIQUE;
CREATE CONSTRAINT ON (attack_vector:AttackVector) ASSERT attack_vector.name IS UNIQUE;
CREATE CONSTRAINT ON (vendor:Vendor) ASSERT vendor.name IS UNIQUE;
CREATE CONSTRAINT ON (product:Product) ASSERT product.name IS UNIQUE;

CALL apoc.periodic.commit("
		CALL apoc.load.json('file:///var/lib/neo4j/nvd-300.json') YIELD value AS nvd
UNWIND nvd.CVE_Items as vuln
MERGE (cve:CVE {
    attack_complexity: COALESCE(vuln.impact.baseMetricV3.cvssV3.attackComplexity, 'NA'),
    availability_impact: COALESCE(vuln.impact.baseMetricV3.cvssV3.availabilityImpact, 'NA'),
    base_score: COALESCE(vuln.impact.baseMetricV3.cvssV3.baseScore, -1),
    base_severity: COALESCE(vuln.impact.baseMetricV3.cvssV3.baseSeverity, 'NA'),
    confidentiality_impact: COALESCE(vuln.impact.baseMetricV3.cvssV3.confidentialityImpact, 'NA'),
    description: [desc IN vuln.cve.description.description_data WHERE desc.lang = 'en'| desc.value],
    exploitability_score: COALESCE(vuln.impact.baseMetricV3.exploitabilityScore, -1),
    impact_score: COALESCE(vuln.impact.baseMetricV3.impactScore, -1),
    integrity_impact: COALESCE(vuln.impact.baseMetricV3.cvssV3.integrityImpact, 'NA'),
    name: vuln.cve.CVE_data_meta.ID,
    privileges_required: COALESCE(vuln.impact.baseMetricV3.cvssV3.privilegesRequired, 'NA'),
    published: apoc.date.fromISO8601(apoc.text.replace(vuln.publishedDate,'Z$',':00Z')),
    scope: COALESCE(vuln.impact.baseMetricV3.cvssV3.scope, 'NA'),
    user_interaction: COALESCE(vuln.impact.baseMetricV3.cvssV3.userInteraction, 'NA')
    })

FOREACH (cvss_vector_string IN vuln.impact.baseMetricV3.cvssV3.vectorString |
    MERGE (cvss:CVSS {
        name: apoc.text.replace(cvss_vector_string,'CVSS\\:3\\.0\\/','')
        })
    MERGE (cve)-[:IS_ENCODED_AS]->(cvss)
    )

FOREACH (cve_attack_vector IN vuln.impact.baseMetricV3.cvssV3.attackVector |
    MERGE (attack_vector:AttackVector {name: cve_attack_vector})
    MERGE (cve)-[:IS_ATTACKABLE_THROUGH]-(attack_vector)
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
                MERGE (product_version)-[:VERSION_OF]-(product)
                MERGE (cve)-[:AFFECTS]->(product_version))
            )
    )
	", {batchSize:1000, parallel:false});