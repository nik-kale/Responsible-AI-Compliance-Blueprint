# Data Provenance Documentation

## Training Dataset

**Dataset Name:** Customer Feedback Corpus v2.0
**Source:** Internal customer feedback system
**Collection Period:** 2022-01-01 to 2023-12-31
**Sample Size:** 100,000 samples

### Data Collection
- **Method:** Automated extraction from customer feedback portal
- **Consent:** Customers consent to feedback analysis (Terms of Service, Section 4.2)
- **PII Handling:** Email addresses and names removed during extraction

### Data Processing
1. **Deduplication:** Removed exact duplicates (5.2% of original dataset)
2. **Language Filtering:** Retained only English text (91% of samples)
3. **Quality Filtering:** Removed samples < 10 words or > 500 words
4. **Balancing:** Stratified sampling to achieve 50/50 positive/negative split
5. **Anonymization:** Removed product-specific identifiers, customer IDs

### Data Splits
- Training: 80,000 samples (80%)
- Validation: 10,000 samples (10%)
- Test: 10,000 samples (10%)

**Split Method:** Stratified random sampling by sentiment and product category

### Quality Metrics
- **Inter-annotator Agreement:** 0.89 (Krippendorff's alpha)
- **Label Quality Check:** Manual review of 1,000 random samples (96% agreement)
- **Completeness:** No missing values in text or label fields

### Storage and Access
- **Location:** AWS S3 bucket `s3://example-ml-data/sentiment/v2.0/`
- **Access Control:** Restricted to ML Engineering team via IAM roles
- **Encryption:** AES-256 encryption at rest
- **Retention:** 7 years per data retention policy

### Checksums
See `checksums.txt` for SHA256 hashes of all dataset files.

### Known Limitations
1. Bias toward common product categories (electronics: 35%, home goods: 28%)
2. Temporal bias: More recent feedback overrepresented
3. Platform bias: Web portal feedback only (no mobile app, email, or chat)

### Last Updated
2024-01-05 by ML Engineering Team
