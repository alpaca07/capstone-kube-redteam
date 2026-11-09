// knowledge 지식그래프 제약조건·색인 — schema.LABELS 에서 자동생성(수정 말고 재생성).
// 적재 전 1회 적용:  cypher-shell -u neo4j -p $NEO4J_PASSWORD < knowledge/bootstrap.cypher
// 또는:  python -m knowledge --bootstrap
// Neo4j 5.x 문법. 4.x 면 REQUIRE -> ASSERT.
CREATE CONSTRAINT kg_advisory_id IF NOT EXISTS FOR (n:Advisory) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_attackoutcome_id IF NOT EXISTS FOR (n:AttackOutcome) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_attackvector_id IF NOT EXISTS FOR (n:AttackVector) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_capec_id IF NOT EXISTS FOR (n:CAPEC) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_cpe_id IF NOT EXISTS FOR (n:CPE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_cleanupaction_id IF NOT EXISTS FOR (n:CleanupAction) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_configuration_id IF NOT EXISTS FOR (n:Configuration) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_evidencereference_id IF NOT EXISTS FOR (n:EvidenceReference) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_evidencetype_id IF NOT EXISTS FOR (n:EvidenceType) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_expectedresult_id IF NOT EXISTS FOR (n:ExpectedResult) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_knowledgerevision_id IF NOT EXISTS FOR (n:KnowledgeRevision) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_knowledgesource_id IF NOT EXISTS FOR (n:KnowledgeSource) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_platform_id IF NOT EXISTS FOR (n:Platform) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_precondition_id IF NOT EXISTS FOR (n:Precondition) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_procedure_id IF NOT EXISTS FOR (n:Procedure) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_product_id IF NOT EXISTS FOR (n:Product) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_resultcondition_id IF NOT EXISTS FOR (n:ResultCondition) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_servicetype_id IF NOT EXISTS FOR (n:ServiceType) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_subtechnique_id IF NOT EXISTS FOR (n:SubTechnique) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_tactic_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_technique_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_technology_id IF NOT EXISTS FOR (n:Technology) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT kg_verificationrecord_id IF NOT EXISTS FOR (n:VerificationRecord) REQUIRE n.id IS UNIQUE;
