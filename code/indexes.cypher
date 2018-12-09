// explicitly create other non-unique indices on CVE
// we are going to create a lot b/c, as a research
// tool this should have a lot of potential entry points
// (e.g. search might start w/ all CVEs that do not require
// user interaction, or have a base_score over 9.)
// *Not* creating an index on the CVE text description,
// because this is not a document store, and if you want
// full text search to find your CVEs, you should probably
// use nvd.nist.gov.
CREATE INDEX ON :CVE(published);

CREATE INDEX ON :CVE(`v2.access_complexity`);
CREATE INDEX ON :CVE(`v2.authentication`);
CREATE INDEX ON :CVE(`v2.availability_impact`);
CREATE INDEX ON :CVE(`v2.base_score`);
CREATE INDEX ON :CVE(`v2.confidentiality_impact`);
CREATE INDEX ON :CVE(`v2.exploitability_score`);
CREATE INDEX ON :CVE(`v2.impact_score`);
CREATE INDEX ON :CVE(`v2.integrity_impact`);
CREATE INDEX ON :CVE(`v2.severity`);
CREATE INDEX ON :CVE(`v2.obtain_all_privilege`);
CREATE INDEX ON :CVE(`v2.obtain_other_privilege`);
CREATE INDEX ON :CVE(`v2.obtain_other_privilege`);
CREATE INDEX ON :CVE(`v2.obtain_user_privilege`);
CREATE INDEX ON :CVE(`v2.user_interaction_required`);
CREATE INDEX ON :CVE(`v2.vector_string`);

CREATE INDEX ON :CVE(`v3.attack_complexity`);
CREATE INDEX ON :CVE(`v3.availability_impact`);
CREATE INDEX ON :CVE(`v3.base_score`);
CREATE INDEX ON :CVE(`v3.base_severity`);
CREATE INDEX ON :CVE(`v3.confidentiality_impact`);
CREATE INDEX ON :CVE(`v3.exploitability_score`);
CREATE INDEX ON :CVE(`v3.impact_score`);
CREATE INDEX ON :CVE(`v3.integrity_impact`);
CREATE INDEX ON :CVE(`v3.privileges_required`);
CREATE INDEX ON :CVE(`v3.scope`);
CREATE INDEX ON :CVE(`v3.user_interaction`);
CREATE INDEX ON :CVE(`v3.vector_string`);